FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY helper.py c2_server.py exfil_server.py staging_server.py op.py ./

RUN mkdir -p /app/exfil /app/logs

CMD ["python", "c2_server.py"]
