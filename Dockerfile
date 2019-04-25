FROM       ubuntu:18.10
MAINTAINER elceef@gmail.com

WORKDIR    /opt/dnstwist
RUN        apt-get update && apt-get install -y python-dnspython python-geoip python-whois \
python-requests python-ssdeep

COPY       . /opt/dnstwist/
ENTRYPOINT ["./dnstwist.py"]
