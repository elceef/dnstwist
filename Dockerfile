# docker build -t dnstwist .
# docker build -t dnstwist:phash --build-arg phash=1 .

FROM debian:stable-slim
MAINTAINER elceef@gmail.com

WORKDIR /opt/dnstwist

ARG phash

RUN apt-get update && \
export DEBIAN_FRONTEND=noninteractive && \
apt-get install -y --no-install-recommends python3-dnspython python3-tld python3-geoip python3-idna ca-certificates && \
apt-get install -y python3-ssdeep python3-tlsh && \
if [ -n "$phash" ]; then apt-get install -y --no-install-recommends python3-pil python3-selenium chromium-driver; fi && \
apt-get autoremove -y && \
apt-get clean && \
rm -rf /var/lib/apt/lists/*

COPY dnstwist.py /opt/dnstwist/
COPY dictionaries /opt/dnstwist/dictionaries/

ENTRYPOINT ["./dnstwist.py"]
