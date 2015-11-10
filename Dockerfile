FROM       ubuntu:15.04
MAINTAINER julien@rottenberg.info


WORKDIR    /opt/dnstwist
RUN        apt-get update && apt-get install -y python-dnspython python-geoip python-whois \
python-requests python-ssdeep

COPY       . /opt/dnstwist/
ENTRYPOINT ["./dnstwist.py"]
