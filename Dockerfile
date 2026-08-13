# Start from a small, stable Python image.
FROM python:3.12-slim

# All following commands run inside /app in the container.
WORKDIR /app

# Copy just the requirements first and install them. Docker caches this
# layer, so rebuilds are fast unless your dependencies change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code and the trained model into the image.
COPY main.py .
COPY agent_firewall.py .
COPY classifier.joblib .

# Tell Azure which port the app listens on (it reads this line).
EXPOSE 8000

# The command that starts the server when the container runs.
# host 0.0.0.0 is required inside a container (not 127.0.0.1).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]