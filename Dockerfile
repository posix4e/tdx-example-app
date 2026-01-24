FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies (SDK is included locally)
COPY app/requirements.txt .
COPY easyenclave-sdk/ /tmp/easyenclave-sdk/
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY app/ .

# Run
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
