FROM python:3.12-slim
WORKDIR /app
COPY requirements-healthbridge.txt .
RUN pip install --no-cache-dir -r requirements-healthbridge.txt
COPY healthbridge_main.py .
ENV PORT=8080
CMD ["sh","-c","uvicorn healthbridge_main:app --host 0.0.0.0 --port ${PORT:-8080}"]
