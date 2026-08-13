# Aegis AI Gateway

A security proxy for AI. It guards two surfaces: the **words** an AI exchanges
with a user (`/chat`) and the **actions** an AI agent takes in the world
(`/agent`). It blocks prompt-injection and jailbreak attacks before they reach
the model, redacts personal data from responses, and enforces least-privilege on
every tool an agent tries to run.

## How it works

### Chat guard (`/chat`)

Every request passes through three inbound checks before the model is called:

1. Pattern match for known attack phrases
2. Azure AI Content Safety Prompt Shields
3. A classifier trained on the `deepset/prompt-injections` dataset

Every response is scanned for PII (emails, phone numbers, SSNs, card numbers) and redacted before it is returned. If a safety check fails, the gateway blocks the request rather than letting it through.

### Agent tool-call firewall (`/agent`)

Modern AI systems are agents that take actions — reading files, calling APIs,
running shell commands. Before an agent runs a tool, the intended call passes
through an action firewall aligned with the **OWASP Top 10 for Agentic
Applications (2026)**:

1. **Kill switch** — one env var halts all agent action at once
2. **Rate limit** — per-identity budget stops runaway autonomy loops
3. **Least-privilege allowlist** — only registered tools may run; unknown tools denied
4. **Argument injection scan** — reuses the chat guard's detection on tool arguments
5. **Per-tool argument policy** — blocks SSRF (internal hosts / cloud metadata), path traversal, sensitive-file access, and destructive shell commands
6. **Human-in-the-loop** — high-impact tools (`write_file`, `run_shell`, `send_email`) require explicit approval

Every allow/block decision is logged with the identity, tool, and the control that decided it.

## Tech

Python, FastAPI, Azure OpenAI, Azure AI Content Safety, scikit-learn, Docker, Azure Container Apps, Key Vault, Entra ID, Bicep. Agentic controls mapped to the OWASP Top 10 for Agentic Applications (2026).

## Run locally

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd src                                # run from src/ so the model path resolves
python ../scripts/train_classifier.py # builds classifier.joblib here in src/
uvicorn main:app --reload
```

Add a `.env` in the repo root with your Azure OpenAI and Content Safety endpoints and keys, then open http://127.0.0.1:8000/docs to test both `/chat` and `/agent`.

## More

- Architecture and threat model: [ARCHITECTURE.md](ARCHITECTURE.md)
- Test results: [TESTS.md](TESTS.md)