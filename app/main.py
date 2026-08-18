import os
import re
from pathlib import Path

import requests
import joblib
from fastapi import FastAPI, Request
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()  

app = FastAPI()

# Azure OpenAI connection 
client = OpenAI(
    base_url=os.environ["AZURE_OPENAI_ENDPOINT"],
    api_key=os.environ["AZURE_OPENAI_KEY"],
)
DEPLOYMENT = os.environ["AZURE_OPENAI_DEPLOYMENT"]

# Azure AI Content Safety (Prompt Shields) settings
CONTENT_SAFETY_ENDPOINT = os.environ["CONTENT_SAFETY_ENDPOINT"].rstrip("/")
CONTENT_SAFETY_KEY = os.environ["CONTENT_SAFETY_KEY"]

# Load the trained Layer 3 classifier once, when the app starts.
# Default path is models/classifier.joblib next to this package; override with
# CLASSIFIER_PATH if the model lives somewhere else.
DEFAULT_CLASSIFIER_PATH = Path(__file__).resolve().parent.parent / "models" / "classifier.joblib"
CLASSIFIER_PATH = os.environ.get("CLASSIFIER_PATH", str(DEFAULT_CLASSIFIER_PATH))
classifier = joblib.load(CLASSIFIER_PATH)

# INBOUND GUARD 
INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore the above",
    "disregard previous",
    "forget your instructions",
    "reveal your prompt",
    "developer mode",
    "you are now",
    "pretend to be",
    "jailbreak",
    "do anything now",
    "dan mode",
    "override your",
    "bypass your",
]


def check_patterns(message: str):
    """Layer 1: block if the message contains a known attack phrase."""
    lowered = message.lower()
    for pattern in INJECTION_PATTERNS:
        if pattern in lowered:
            return True, f"layer1 matched attack phrase: '{pattern}'"
    return False, ""


def check_prompt_shield(message: str):
    """Layer 2: ask Azure Prompt Shields whether this looks like an attack."""
    url = f"{CONTENT_SAFETY_ENDPOINT}/contentsafety/text:shieldPrompt?api-version=2024-09-01"
    headers = {
        "Ocp-Apim-Subscription-Key": CONTENT_SAFETY_KEY,
        "Content-Type": "application/json",
    }
    body = {"userPrompt": message, "documents": []}
    try:
        response = requests.post(url, headers=headers, json=body, timeout=10)
        response.raise_for_status()
        result = response.json()
        if result["userPromptAnalysis"]["attackDetected"]:
            return True, "layer2 Prompt Shields flagged an attack"
        return False, ""
    except Exception as e:
        # Fail closed: if the safety check breaks, block rather than allow.
        print(f"[LAYER2 ERROR] {e}")
        return True, "layer2 check failed, blocking to be safe"

def check_classifier(message: str):
    """
    Layer 3: your own trained model's opinion on the message.
    predict() returns 1 for attack, 0 for safe.
    predict_proba() gives how confident it is, which we include in the reason.
    """
    prediction = classifier.predict([message])[0]
    if prediction == 1:
        confidence = classifier.predict_proba([message])[0][1]
        return True, f"layer3 classifier flagged attack (confidence {confidence:.2f})"
    return False, ""

def check_inbound(message: str):
    """Run the inbound layers in order."""
    blocked, reason = check_patterns(message)       # Layer 1
    if blocked:
        return True, reason

    blocked, reason = check_prompt_shield(message)  # Layer 2
    if blocked:
        return True, reason

    blocked, reason = check_classifier(message)     # Layer 3 
    if blocked:
        return True, reason

    return False, ""


# ==================================================================
# OUTBOUND GUARD 
# ==================================================================
# Each entry is a label plus a regular expression that matches that kind of
# personal data. A regex is just a pattern: \d means "a digit", {4} means
# "exactly four of them", and so on. You don't need to memorize these — the
# comments explain what each one catches.
PII_PATTERNS = {
    # name@example.com
    "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    # 123-45-6789  (US Social Security Number)
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    # 1234 5678 9012 3456  (16-digit card, spaces or dashes optional)
    "CREDIT_CARD": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
    # (555) 123-4567  /  555-123-4567  /  +1 555 123 4567
    "PHONE": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
}


def scan_and_redact_pii(text: str):
    """
    Look through the model's reply for personal data and black it out.

    Returns:
      - cleaned:    the reply with any PII replaced by [REDACTED ...]
      - redactions: a list of the kinds of PII we found (e.g. ["EMAIL"])
    We redact CREDIT_CARD and SSN before PHONE so a card number isn't
    partly matched as a phone number.
    """
    cleaned = text
    redactions = []
    for label, pattern in PII_PATTERNS.items():
        if re.search(pattern, cleaned):          # is there at least one match?
            cleaned = re.sub(pattern, f"[REDACTED {label}]", cleaned)  # replace all matches
            redactions.append(label)
    return cleaned, redactions


# Phrases that suggest the model may have been tricked into revealing its setup.
LEAK_MARKERS = [
    "my system prompt",
    "my instructions are",
    "i was instructed to",
    "here are my instructions",
    "my initial prompt",
]


def check_response_hijacked(text: str):
    """Light check: does the reply look like it's leaking its own instructions?"""
    lowered = text.lower()
    for marker in LEAK_MARKERS:
        if marker in lowered:
            return True
    return False


def check_outbound(reply: str):
    """
    Run the outbound guard on the model's reply.

    Returns:
      - final_reply: the reply after PII redaction (safe to send to the user)
      - info:        a small dict describing what the guard found/did
    """
    final_reply, redactions = scan_and_redact_pii(reply)
    possible_leak = check_response_hijacked(final_reply)
    info = {"pii_redacted": redactions, "possible_leak": possible_leak}
    return final_reply, info


# Request shape 
class ChatRequest(BaseModel):
    message: str


@app.post("/chat")
def chat(request: ChatRequest, http_request: Request):
    user = http_request.headers.get("x-ms-client-principal-name", "anonymous")
    print(f"[USER] {user}")
    # 1) INBOUND GUARD — check the request before calling the model.
    is_blocked, reason = check_inbound(request.message)
    if is_blocked:
        print(f"[BLOCKED] {reason} | message={request.message!r}")
        return {"blocked": True, "reason": reason, "reply": None}

    # 2) Call the model.
    print(f"[ALLOWED] message={request.message!r}")
    response = client.chat.completions.create(
        model=DEPLOYMENT,
        messages=[{"role": "user", "content": request.message}],
    )
    reply = response.choices[0].message.content

    # 3) OUTBOUND GUARD — check the model's answer before returning it.
    final_reply, outbound = check_outbound(reply)
    if outbound["pii_redacted"] or outbound["possible_leak"]:
        print(f"[OUTBOUND] redacted={outbound['pii_redacted']} leak={outbound['possible_leak']}")

    # 4) Return the cleaned reply plus a note about what the outbound guard did.
    return {"blocked": False, "reason": None, "reply": final_reply, "outbound": outbound}