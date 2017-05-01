FROM       ubuntu:15.04
MAINTAINER dcumbo@gmail.com


WORKDIR    /opt/dnstwist
RUN        apt-get update && apt-get install -y python-dnspython python-geoip python-whois \
python-requests python-ssdeep python-Flask python-Flask-RESTful python-Flask-API

COPY       . /opt/dnstwist/
ENTRYPOINT ["./dnstwistapi.py"]
