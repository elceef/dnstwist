# Execute the following command to build the image: tar -czh . | docker build -t dnstwist_webapp -

FROM       debian:stable-slim
MAINTAINER marcin@ulikowski.pl

WORKDIR    /opt/dnstwist

RUN        apt-get update && \
           apt-get install -y --no-install-recommends python3-idna python3-tld python3-dnspython python3-geoip gunicorn3 python3-flask

COPY       ./webapp.py /opt/dnstwist/
COPY       ./webapp.html /opt/dnstwist/
COPY       ./dnstwist.py /opt/dnstwist/

EXPOSE     8000

CMD        ["gunicorn3", "webapp:app", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "3", "--log-level", "debug"]
