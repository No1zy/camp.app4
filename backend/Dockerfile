FROM python:3.9-alpine

WORKDIR /sample_app

COPY ./sample_app /sample_app
COPY ./script /script

RUN apk add build-base libffi-dev && \
    pip install -r requirements.txt

ENTRYPOINT ["sh", "/script/entrypoint.sh"]
