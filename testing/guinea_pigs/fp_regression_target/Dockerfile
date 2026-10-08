# RedAmon false-positive regression guinea pig. Stdlib Python; openssl only to
# mint the self-signed certificate the SNI edge presents (no key is committed).
FROM python:3.11-alpine

RUN apk add --no-cache openssl

WORKDIR /app
COPY server.py /app/server.py
COPY static /app/static

ENV PYTHONUNBUFFERED=1

EXPOSE 80 443
CMD ["python3", "/app/server.py"]
