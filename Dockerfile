FROM       ubuntu:18.04
MAINTAINER elceef@gmail.com

WORKDIR    /opt/dnstwist
RUN        apt-get update && apt-get upgrade -y && apt-get install -y python-dnspython python-geoip python-whois \
python-requests python-ssdeep python-cffi

COPY       . /opt/dnstwist/
ENTRYPOINT ["./dnstwist.py"]
