FROM       ubuntu:18.10
MAINTAINER elceef@gmail.com

WORKDIR    /opt/dnstwist
RUN        apt-get update && \
           apt-get install -y --no-install-recommends python3-dnspython python3-geoip python3-whois python3-requests python3-ssdeep locales && \
           locale-gen en_US.UTF-8
ENV        LC_ALL=en_US.UTF-8
ENV        LANG=en_US.UTF-8
ENV        LANGUAGE=en_US.UTF-8

COPY       . /opt/dnstwist/
ENTRYPOINT ["./dnstwist.py"]
