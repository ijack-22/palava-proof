FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install -r requirements.txt

COPY backend/app/ .

EXPOSE 8080

CMD gunicorn app:app --bind 0.0.0.0:$PORT
