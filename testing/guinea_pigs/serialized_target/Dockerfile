FROM python:3.12-slim

WORKDIR /app
COPY payloads.py server.py /app/

# Port 80 so a plain-IP recon target is found by default httpx 80/443 probing,
# mirroring web-cache-poisoning. Inert, stdlib-only throwaway lab; runs as root
# only to bind :80. Never expose to an untrusted network.
EXPOSE 80
CMD ["python3", "server.py"]
