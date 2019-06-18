FROM       ubuntu:18.10
MAINTAINER elceef@gmail.com

WORKDIR    /opt/dnstwist
RUN        apt-get update && apt-get install -y python3-dnspython python3-geoip python3-whois \
python3-requests python3-ssdeep

COPY       . /opt/dnstwist/
ENTRYPOINT ["./dnstwist.py"]
