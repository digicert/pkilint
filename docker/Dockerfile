FROM python:3.11-slim

LABEL authors="DigiCert, Inc."

ARG WHEELFILE

WORKDIR /usr/src/app

COPY dist/$WHEELFILE ./

RUN pip install --no-cache-dir "$WHEELFILE[rest]" uvicorn gunicorn

RUN rm $WHEELFILE

COPY entrypoint.py ./

ENTRYPOINT ["python", "entrypoint.py"]
