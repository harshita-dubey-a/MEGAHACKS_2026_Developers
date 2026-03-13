FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (e.g., nuclei if available via apt or curl)
# Installing curl and others
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Install Nuclei (Simulated installation for demo, in real life: fetch binary)
# RUN curl -s -L https://github.com/projectdiscovery/nuclei/releases/download/v2.9.6/nuclei_2.9.6_linux_amd64.zip ...

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
