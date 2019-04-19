FROM python:2.7.16-alpine

MAINTAINER coolboi567 <PrashantShahi567@gmail.com>

WORKDIR /opt/dnstwist

COPY . /opt/dnstwist/

RUN apk update && \
	apk add  --virtual .build-deps alpine-sdk libffi-dev geoip-dev && \
	BUILD_LIB=1 pip install -r requirements.txt && \
	apk del .build-deps

ENTRYPOINT ["python", "dnstwist.py"]