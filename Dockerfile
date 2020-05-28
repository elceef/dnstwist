FROM debian:stable-slim
MAINTAINER elceef@gmail.com

WORKDIR /opt/dnstwist
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-dnspython python3-tld python3-geoip python3-whois python3-requests python3-ssdeep && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY dnstwist.py /opt/dnstwist/
COPY dictionaries /opt/dnstwist/dictionaries/

ENTRYPOINT ["./dnstwist.py"]
