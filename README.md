# Aegis AI Gateway

A security proxy that sits in front of Azure OpenAI. It blocks prompt injection
and jailbreak attempts before they reach the model, and redacts personal data
from the model's answers before they reach the user.

## How it works

Every request passes three inbound checks before the model is called. They run
cheapest first, and the first one that flags the request stops the rest.

1. Pattern match against a list of known attack phrases, in process
2. Azure AI Content Safety Prompt Shields, a hosted detection service
3. A classifier trained here on the public `deepset/prompt-injections` dataset

Every response is scanned for personal data (emails, phone numbers, US Social
Security numbers, card numbers) and redacted before it is returned, and checked
for signs that the model is disclosing its own instructions. If a safety check
itself fails, the gateway blocks the request rather than letting it through.

## Tech

Python, FastAPI, Azure OpenAI, Azure AI Content Safety, scikit-learn, Docker,
Azure Container Apps, Key Vault, Entra ID, Bicep.

## Layout

```
app/                  FastAPI gateway (inbound and outbound guards, /chat route)
models/               trained classifier, loaded at startup
scripts/              training script for the classifier
infra/                Bicep template for the Azure deployment
docs/                 architecture, metrics, test results, build manual
Dockerfile            container image for Azure Container Apps
```

## Run locally

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python scripts/train_classifier.py      # writes models/classifier.joblib
uvicorn app.main:app --reload
```

Add a `.env` file with your Azure OpenAI and Content Safety endpoints and keys,
then open http://127.0.0.1:8000/docs to send test requests.

## Build and deploy

```bash
docker build -t <registry>.azurecr.io/aegis-gateway:latest .
docker push <registry>.azurecr.io/aegis-gateway:latest

az deployment group create \
  --resource-group <resource-group> \
  --template-file infra/main.bicep \
  --parameters containerImage=<registry>.azurecr.io/aegis-gateway:latest \
               acrLoginServer=<registry>.azurecr.io \
               acrName=<registry> \
               openAiEndpoint=<endpoint> \
               openAiDeployment=<deployment> \
               contentSafetyEndpoint=<endpoint> \
               openAiKey=<key> \
               contentSafetyKey=<key>
```

The keys are secure parameters. They are written into Key Vault by the template
and never stored in the file or in app settings.

## More

- Architecture and threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Classifier evaluation: [docs/METRICS.md](docs/METRICS.md)
- Test results: [docs/TESTS.md](docs/TESTS.md)

