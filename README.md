# Aegis AI Gateway

A security proxy in front of Azure OpenAI. It blocks prompt-injection and jailbreak attacks before they reach the model, and redacts personal data from responses before they reach the user.

## How it works

Every request passes through three inbound checks before the model is called:

1. Pattern match for known attack phrases
2. Azure AI Content Safety Prompt Shields
3. A classifier trained on the `deepset/prompt-injections` dataset

Every response is scanned for PII (emails, phone numbers, SSNs, card numbers) and redacted before it is returned. If a safety check fails, the gateway blocks the request rather than letting it through.

## Tech

Python, FastAPI, Azure OpenAI, Azure AI Content Safety, scikit-learn, Docker, Azure Container Apps, Key Vault, Entra ID, Bicep.

## Run locally

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python train_classifier.py      # builds classifier.joblib
uvicorn main:app --reload
```

Add a `.env` with your Azure OpenAI and Content Safety endpoints and keys, then open http://127.0.0.1:8000/docs to test.

## More

- Architecture and threat model: [ARCHITECTURE.md](ARCHITECTURE.md)
- Test results: [TESTS.md](TESTS.md)