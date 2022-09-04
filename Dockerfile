FROM debian:stable-slim
MAINTAINER elceef@gmail.com

WORKDIR /opt/dnstwist
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-dnspython python3-tld python3-geoip python3-whois python3-ssdeep ca-certificates && \
#   apt-get install -y --no-install-recommends python3-pil python3-selenium chromium-driver && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY dnstwist.py /opt/dnstwist/
COPY dictionaries /opt/dnstwist/dictionaries/

ENTRYPOINT ["./dnstwist.py"]
