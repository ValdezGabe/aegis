import os
import requests                      
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()  # load all values from your .env file

app = FastAPI()

# Azure Open AI Connection
client = OpenAI(
    base_url=os.environ["AZURE_OPENAI_ENDPOINT"],
    api_key=os.environ["AZURE_OPENAI_KEY"],
)
DEPLOYMENT = os.environ["AZURE_OPENAI_DEPLOYMENT"]

# Azure AI Content Safety (Prompt Shields) settings 
# Read Key and Endpoint
CONTENT_SAFETY_ENDPOINT = os.environ["CONTENT_SAFETY_ENDPOINT"].rstrip("/")
CONTENT_SAFETY_KEY = os.environ["CONTENT_SAFETY_KEY"]


# ------------------------------------------------------------------
# INBOUND GUARD — LAYER 1: known-attack pattern check
# ------------------------------------------------------------------
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


# ------------------------------------------------------------------
# INBOUND GUARD — LAYER 2: Azure AI Content Safety Prompt Shields
# ------------------------------------------------------------------
def check_prompt_shield(message: str):
    """
    Layer 2: send the message to Microsoft's Prompt Shields service, which uses
    machine learning to detect injection/jailbreak attempts that Layer 1 misses.

    Returns (is_blocked, reason), same shape as Layer 1 so the two combine cleanly.
    """
    # The Prompt Shields endpoint. The api-version is the current supported one;
    # if Azure ever rejects it, this is the value to update.
    url = f"{CONTENT_SAFETY_ENDPOINT}/contentsafety/text:shieldPrompt?api-version=2024-09-01"

    # The key goes in this header. "Content-Type" tells the service we're sending JSON.
    headers = {
        "Ocp-Apim-Subscription-Key": CONTENT_SAFETY_KEY,
        "Content-Type": "application/json",
    }

    # "userPrompt" is the message we want analyzed. We send no documents here.
    body = {"userPrompt": message, "documents": []}

    try:
        # Call the service. timeout stops us hanging forever if Azure is slow.
        response = requests.post(url, headers=headers, json=body, timeout=10)
        response.raise_for_status()          # raise an error on a bad HTTP status
        result = response.json()             # turn the JSON reply into a Python dict

        # The reply looks like: {"userPromptAnalysis": {"attackDetected": true/false}, ...}
        attack_detected = result["userPromptAnalysis"]["attackDetected"]

        if attack_detected:
            return True, "layer2 Prompt Shields flagged an attack"
        return False, ""

    except Exception as e:
        print(f"[LAYER2 ERROR] {e}")
        return True, "layer2 check failed, blocking to be safe"


def check_inbound(message: str):
    """
    Runs the inbound guard layers in order, cheapest first.
    If any layer blocks, we stop and return its decision immediately.
    """
    # Layer 1: fast local pattern check
    blocked, reason = check_patterns(message)
    if blocked:
        return True, reason

    # Layer 2: ML-based Prompt Shields check
    blocked, reason = check_prompt_shield(message)
    if blocked:
        return True, reason

    # Passed every layer
    return False, ""


# --- Request shape  ---
class ChatRequest(BaseModel):
    message: str


@app.post("/chat")
def chat(request: ChatRequest):
    # Run the full inbound guard BEFORE calling the model.
    is_blocked, reason = check_inbound(request.message)

    if is_blocked:
        print(f"[BLOCKED] {reason} | message={request.message!r}")
        return {"blocked": True, "reason": reason, "reply": None}

    # Clean message -> call the model as normal.
    print(f"[ALLOWED] message={request.message!r}")
    response = client.chat.completions.create(
        model=DEPLOYMENT,
        messages=[{"role": "user", "content": request.message}],
    )
    return {"blocked": False, "reason": None, "reply": response.choices[0].message.content}