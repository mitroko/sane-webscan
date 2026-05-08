FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    sane-utils sane-airscan python3 curl imagemagick \
    && rm -rf /var/lib/apt/lists/*

COPY scan.py /var/uwsgi/scan.py
RUN mkdir -p /var/lib/sanewebscan /var/uwsgi/sanewebscan
RUN chown 1000:0 /var/lib/sanewebscan
RUN chmod 0755 /var/lib/sanewebscan
RUN usermod -aG scanner ubuntu
COPY --chmod=ugo=r scan.py /var/uwsgi/sanewebscan/scan.py
WORKDIR /var/lib/sanewebscan

USER ubuntu
ENTRYPOINT [ "/usr/bin/python3", "/var/uwsgi/sanewebscan/scan.py" ]
