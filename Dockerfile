FROM python:3.11-slim

WORKDIR /app

COPY c2_server.py exfil_server.py implant_client.py op.py stager.sh ./

RUN mkdir -p /app/exfil /app/logs

CMD ["python", "c2_server.py"]
