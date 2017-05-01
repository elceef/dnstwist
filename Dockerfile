FROM       ubuntu:16.10
MAINTAINER dcumbo@gmail.com

RUN        apt-get update && apt-get install -y python-dnspython python-geoip python-whois \
python-requests python-ssdeep python-flask python-flask-restful python-flask-api

WORKDIR    /opt/dnstwist
COPY       . /opt/dnstwist/
EXPOSE     5000

ENTRYPOINT  ["python"]
CMD         ["dnstwistapi.py"]
