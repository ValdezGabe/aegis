import os
import re
import requests
import joblib
from fastapi import FastAPI, Request
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI
from opentelemetry import trace

import agent_firewall
import telemetry

load_dotenv()

app = FastAPI()

# Wire OpenTelemetry: traces + metrics for every guard layer, exported to an
# OTLP backend (Grafana/Jaeger/Collector) or the console in local dev.
telemetry.setup_telemetry(app)

# Azure OpenAI connection 
client = OpenAI(
    base_url=os.environ["AZURE_OPENAI_ENDPOINT"],
    api_key=os.environ["AZURE_OPENAI_KEY"],
)
DEPLOYMENT = os.environ["AZURE_OPENAI_DEPLOYMENT"]

# Azure AI Content Safety (Prompt Shields) settings
CONTENT_SAFETY_ENDPOINT = os.environ["CONTENT_SAFETY_ENDPOINT"].rstrip("/")
CONTENT_SAFETY_KEY = os.environ["CONTENT_SAFETY_KEY"]

# Load your trained Layer 3 classifier once, when the app starts.
classifier = joblib.load("classifier.joblib")

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
    """
    Run the inbound layers in order. Each layer runs inside its own telemetry
    span so a trace shows the timeline of the request through the guard, and the
    latency histogram can break time down per layer. Returns (blocked, reason,
    layer) where `layer` names the check that blocked, or None if all passed.
    """
    with telemetry.layer_span("guard.layer1", "layer1"):
        blocked, reason = check_patterns(message)       # Layer 1
    if blocked:
        return True, reason, "layer1"

    with telemetry.layer_span("guard.layer2", "layer2"):
        blocked, reason = check_prompt_shield(message)  # Layer 2
    if blocked:
        return True, reason, "layer2"

    with telemetry.layer_span("guard.layer3", "layer3"):
        blocked, reason = check_classifier(message)     # Layer 3
    if blocked:
        return True, reason, "layer3"

    return False, "", None


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
    span = trace.get_current_span()  # the auto-created FastAPI server span
    print(f"[USER] {user}")

    # 1) INBOUND GUARD — check the request before calling the model.
    is_blocked, reason, layer = check_inbound(request.message)
    if is_blocked:
        print(f"[BLOCKED] {reason} | message={request.message!r}")
        span.set_attribute("aegis.decision", "blocked")
        span.set_attribute("aegis.blocked_layer", layer)
        telemetry.count(telemetry.requests_total, attributes={"endpoint": "/chat", "decision": "blocked"})
        telemetry.count(telemetry.blocks_total, attributes={"layer": layer})
        return {"blocked": True, "reason": reason, "reply": None}

    # 2) Call the model.
    print(f"[ALLOWED] message={request.message!r}")
    with telemetry.layer_span("model.call", "model"):
        response = client.chat.completions.create(
            model=DEPLOYMENT,
            messages=[{"role": "user", "content": request.message}],
        )
    reply = response.choices[0].message.content

    # 3) OUTBOUND GUARD — check the model's answer before returning it.
    with telemetry.layer_span("guard.outbound", "outbound"):
        final_reply, outbound = check_outbound(reply)
    if outbound["pii_redacted"] or outbound["possible_leak"]:
        print(f"[OUTBOUND] redacted={outbound['pii_redacted']} leak={outbound['possible_leak']}")
        for pii_type in outbound["pii_redacted"]:
            telemetry.count(telemetry.pii_redactions_total, attributes={"type": pii_type})

    span.set_attribute("aegis.decision", "allowed")
    span.set_attribute("aegis.pii_redacted", len(outbound["pii_redacted"]))
    telemetry.count(telemetry.requests_total, attributes={"endpoint": "/chat", "decision": "allowed"})

    # 4) Return the cleaned reply plus a note about what the outbound guard did.
    return {"blocked": False, "reason": None, "reply": final_reply, "outbound": outbound}


# ==================================================================
# AGENTIC TOOL-CALL FIREWALL
# ==================================================================
# The /chat guard above protects a conversation. The /agent guard below protects
# an *action*: before an AI agent runs a tool (read a file, fetch a URL, run a
# shell command), the intended call passes through the checks in
# agent_firewall.py. Only calls that survive every check are allowed to execute.

# A global emergency stop. Set AEGIS_KILL_SWITCH=on in the environment to deny
# every tool call at once — useful if an agent starts misbehaving in production.
agent_firewall.KILL_SWITCH = os.environ.get("AEGIS_KILL_SWITCH", "").lower() in (
    "on",
    "true",
    "1",
)


# Tool arguments are short and often structured (file paths, IDs, recipients),
# so the classifier's default 0.50 decision point produces borderline false
# positives on harmless values. For the action layer we require higher
# confidence before blocking on the classifier alone; Layer 1's exact-phrase
# match is unaffected and still fires on known attacks at any confidence.
AGENT_INJECTION_THRESHOLD = 0.70


def scan_arguments_for_injection(text: str):
    """
    Reuse the chat guard's detection on tool arguments. We run Layer 1 (pattern
    match) and Layer 3 (trained classifier) — the two local, no-network checks —
    so an injected instruction hidden inside a tool argument is caught by the
    same models that protect the chat endpoint. The classifier uses a higher
    confidence threshold here (see AGENT_INJECTION_THRESHOLD) to avoid false
    positives on short structured arguments.
    """
    blocked, reason = check_patterns(text)      # Layer 1: exact attack phrases
    if blocked:
        return True, reason

    confidence = classifier.predict_proba([text])[0][1]   # Layer 3
    if confidence >= AGENT_INJECTION_THRESHOLD:
        return True, f"layer3 classifier flagged attack (confidence {confidence:.2f})"
    return False, ""


class ToolCallRequest(BaseModel):
    tool: str
    arguments: dict = {}


@app.post("/agent")
def agent(request: ToolCallRequest, http_request: Request):
    """
    Guard a single agent tool call.

    The body describes what the agent wants to do, e.g.:
        {"tool": "http_get", "arguments": {"url": "https://example.com"}}

    The firewall returns whether the call is allowed, which control decided it,
    and why. A caller (the agent runtime) should execute the tool only when
    "allowed" is true.
    """
    identity = http_request.headers.get("x-ms-client-principal-name", "anonymous")

    with telemetry.layer_span("agent.tool_call", "agent"):
        decision = agent_firewall.evaluate_tool_call(
            tool=request.tool,
            arguments=request.arguments,
            identity=identity,
            injection_scan=scan_arguments_for_injection,
        )

    # Tag the trace with the decision so a tool call is searchable by tool,
    # outcome, and the control that decided it.
    span = trace.get_current_span()
    outcome = "allowed" if decision["allowed"] else "blocked"
    span.set_attribute("aegis.tool", request.tool)
    span.set_attribute("aegis.decision", outcome)
    span.set_attribute("aegis.control", decision["control"])
    telemetry.count(telemetry.requests_total, attributes={"endpoint": "/agent", "decision": outcome})
    if not decision["allowed"]:
        telemetry.count(telemetry.blocks_total, attributes={"layer": decision["control"]})

    # Audit log: every allow/block decision, who made it, and why. This is the
    # repudiation control for the action layer — a record of what each identity
    # tried to do and how the gateway ruled on it.
    status = "ALLOWED" if decision["allowed"] else "BLOCKED"
    print(
        f"[AGENT {status}] identity={identity} tool={request.tool!r} "
        f"control={decision['control']} reason={decision['reason']!r} "
        f"args={request.arguments!r}"
    )

    return decision