Install notes
=============

- Install as a systemd unit on the host system:
Ubuntu:
    apt update && apt -y install sane-utils sane-airscan python3 curl imagemagick nginx
    systemctl stop avahi-daemon.service # optional / hardening
    systemctl disable avahi-daemon.service # optional / hardening
Configure your scanner by running:
    scanimage -L
Optionally if you want to reduce number of drivers that are going to be tested, copy sane.dll.conf to /etc/sane.d/dll.conf
This way your sane driver list would be limited to net and airscan

If you want to work with your scanner using escl protocol (less reliable, used mostly by epson scanners), you might want to have this in your airscan.conf

  [devices]
  "HP140w"=http://10.0.0.15/eSCL

NOTE: Use doublequotes for device and NO quotes around URI. Specify your device name instead of HP140w
your environment then should look like:

  WEBSCAN_DEVICE=airscan:e0:HP140w

If you want to work with your scanner using wsd protocol (more stable, used mostly by HP and Brother MFDs), you might want to have this in your airscan.conf

  [devices]
  "M570dw"=http://192.168.1.100/WebServices/ScannerService, wsd

NOTE: Use doublequotes for device and NO quotes around URI. Specify your device name instead of M570dw
your environment then should look like:

  WEBSCAN_DEVICE=airscan:w0:M570dw

Create user for your service
    useradd -c "SANE Web Scan app" -d /var/lib/sanewebscan -l -M -N -r -u 985 sane-web-scan
    usermod -aG scanner sane-web-scan
Use sanewebscan.service to manage the service, copy it to /etc/systemd/system and enable
    cp sanewebscan.service /etc/systemd/system
    systemctl daemon-reload
    systemctl enable sanewebscan.service
Create folders and upload the script
    mkdir -p /etc/sysconig /var/uwsgi/sanewebscan /var/lib/sanewebscan
    cp sane.py /var/uwsgi/sanewebscan
Control daemon environment via /etc/sysconfig/sanewebscan, you need to specify your WEBSCAN_DEVICE string there
Start the daemon
    systemctl start sanewebscan.service
Configure nginx
    mkdir /var/www/html/sanewebscan
    cp html/* /var/www/html/sanewebscan/
    cp favicon.ico /var/www/html/sanewebscan/
Use server configuration as in example/sane-webscan.server.nginx for your /etc/nginx/sites-enabled/default or any site you want to configure
    nginx -t
    systemctl enable nginx.service
    systemctl start nginx.service

- Docker/compose way:
Build the docker container:
docker build . -t mitroko/sane-webscan -f Dockerfile
copy docker-conpose.yaml to your /etc/docker/compose/sanewebscan and update it prior to start
Create and populate volumes for services (prior to what is configured in docker-compose.yaml)
Start the service:
    cd /etc/docker/compose/sanewebscan; docker-compose up -d
Control the process logs:
    journalctl -f -u sane-webscan
