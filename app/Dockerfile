FROM python:3.10-slim

WORKDIR /app

# Copy requirements first
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN pip install oqs==0.10.2
# Copy the rest of the app
COPY . .

EXPOSE 5000

CMD ["python", "server.py"]