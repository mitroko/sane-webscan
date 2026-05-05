#!/usr/bin/env python3

import os
import sys
import re
import time
import logging
import subprocess
import unicodedata
from wsgiref.simple_server import make_server, WSGIRequestHandler

WORK_DIR = "/var/lib/sanewebscan"
BIND_ADDR = "127.0.0.1"
BIND_PORT = 9080
APP_ROOT = "/"
LOCK_FILE = "%s/lockfile" % WORK_DIR
LOCK_TTL = 300
SCANIMAGE = '/usr/bin/scanimage'
DEVICE = 'airscan:e0:HP140w'
NFO_FILE = "%s/filename.nfo" % WORK_DIR
JPG_FILE = "%s/scan.jpg" % WORK_DIR
PDF_FILE = "%s/batch.pdf" % WORK_DIR
RESOLUTION = 300
BUFFER = 512


logging.basicConfig(
    level=logging.DEBUG,
    format="[%(levelname)s]: %(message)s"
)
logger = logging.getLogger("SANE Web Scan")


class WebScanHandler(WSGIRequestHandler):
    def address_string(self):
        forwarded = self.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return self.client_address[0]

    def log_message(self, format, *args):
        forwarded = self.headers.get('X-Forwarded-For')
        user = self.headers.get('X-Forwarded-User', '-')
        if forwarded:
            client_ip = forwarded.split(',')[0].strip()
        else:
            client_ip = self.client_address[0]
        message = f"{client_ip} - {user} [{self.log_date_time_string()}] {format % args}"
        sys.stderr.write(message + "\n")
        sys.stderr.flush()

def sanitize_filename(name):
    if not name:
        return "scan"

    # Normalize unicode → ASCII
    name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()

    # Replace unsafe chars
    name = re.sub(r'[^a-zA-Z0-9._-]+', '_', name)

    # Remove leading/trailing junk
    name = name.strip("._-")

    if not name:
        return "scan"

    return name[:64]

def acquire_lock():
    logger.debug(f"Creating lock file {LOCK_FILE}")
    try:
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        time.sleep(1)
        return True
    except FileExistsError:
        logger.debug("Lock file was not created")
        return False

def release_lock():
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
    except:
        pass

def is_lock_stale():
    try:
        return (time.time() - os.path.getmtime(LOCK_FILE)) > LOCK_TTL
    except:
        return False

def response(start_response, status="200 OK", body=b"", headers=[]):
    start_response(status, headers)
    return [body]


def read_filename(environ):
    try:
        size = int(environ.get("CONTENT_LENGTH", 0))
        data = environ["wsgi.input"].read(size).decode()
        for part in data.split("&"):
            if part.startswith("filename="):
                return part.split("=")[1] or "scan"
    except:
        pass
    return "scan"


def run_async(cmd):
    logger.debug("Executing: {}".format(cmd))
    try:
        proc = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True
        )
        logger.debug("Popen executed")
    except Exception as e:
        logger.debug(f"Popen exception: {e}")
        release_lock()

    pid = os.fork()
    if pid == 0:
        try:
            logger.debug("Proc communication started")
            stdout, stderr = proc.communicate()
            if proc.returncode == 0:
                logger.debug("Exit clode 0 lock released")
                release_lock()
            else:
                logger.debug("stderr: {} locak released".format(stderr))
                release_lock()
        finally:
            os._exit(0)


def app(environ, start_response):
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD")
    client = environ.get("HTTP_X_FORWARDED_FOR")

    # logger.debug("Environment: {}".format(environ))
    # logger.debug("uwsgi client: {}".format(client))
    # logger.debug("uwsgi path call: {}".format(path))
    # logger.debug("uwsgi call method: {}".format(method))

    # /healthz
    if path == "/healthz":
        return response(start_response, status="200 OK")

    # /poll
    if path == "/poll":

        if os.path.exists(LOCK_FILE):
            logger.debug("Lock file is in place")
            if is_lock_stale():
                logger.debug("Lock file is stale, releasing")
                release_lock()
            return response(start_response, status="202 Accepted")

        if os.path.exists(JPG_FILE) and os.path.exists(NFO_FILE):
            logger.debug("jpg file is in place and its info file")
            if os.path.getsize(JPG_FILE) > 0:
                logger.debug("jpg file has proper size")
                try:
                    logger.debug("reading filename from nfo")
                    with open(NFO_FILE) as f:
                        name = f.read().strip()
                except:
                    logger.debug("invalid filename replaced with ''")
                    name = ""
                if name:
                    logger.debug("file is returned to a client")
                    with open(JPG_FILE, "rb") as f:
                        return response(
                            start_response,
                            status="200 OK",
                            body=f.read(),
                            headers=[("Content-Type", "image/jpeg"),
                             ("Cache-Control", "no-store"),
                             ("Content-Disposition", f'attachment; filename="{name}.jpg"')]
                        )
            logger.debug("file not returned to a client, probably broken")
            return response(start_response, status="200 OK")

        # batch ready
        logger.debug("batch is ready")
        if os.path.exists(NFO_FILE):
            files = []
            for i in range(100):
                f = f"{WORK_DIR}/batch{i:02d}.jpg"
                if os.path.exists(f):
                    files.append(f)
                else:
                    break
            if files and os.path.getsize(files[-1]) > 0:
                return response(start_response, status="201 Created")

        # cleanup
        logger.debug("Cleanup phase")
        if os.path.exists(NFO_FILE):
            logger.debug("nfo file exists - removing")
            try:
                os.remove(NFO_FILE)
            except:
                logger.debug("Can not remove nfo file")
        if os.path.exists(JPG_FILE):
            logger.debug("jpg file exists - removing")
            try:
                os.remove(JPG_FILE)
            except:
                logger.debug("Can not remove jpg file")
        if os.path.exists(PDF_FILE):
            logger.debug("pdf file exists - removing")
            try:
                os.remove(PDF_FILE)
            except:
                logger.debug("Can not remove pdf file")
        for i in range(100):
            cur_file = f"{WORK_DIR}/batch{i:02d}.jpg"
            if os.path.exists(cur_file):
                try:
                    logger.debug(f"Removing {cur_file}")
                    os.remove(cur_file)
                except:
                    logger.debug(f"Can not remove {cur_file}")
                    pass

        logger.debug("Cleanup completed")
        return response(start_response, status="200 OK")

    # /scan
    if path == "/scan" and method == "POST":
        try:
            filename = sanitize_filename(read_filename(environ))

            if not acquire_lock():
                logger.debug("/scan lock not acquired")
                return response(start_response, status="202 Accepted")

            with open(NFO_FILE, "w") as f:
                f.write(filename)
            logger.debug("/scan filename.nfo created")

            cmd = f"{SCANIMAGE} --device-name={DEVICE} --format=jpeg --resolution={RESOLUTION} --buffer-size={BUFFER} --output-file={JPG_FILE}"
            logger.debug("/scan call: {}".format(cmd))
            run_async(cmd)

            return response(start_response, status="302 Found", headers=[("Location", "scan.html")])
        except Exception as e:
            logger.debug("/scan failed: {}".format(e))
            return response(start_response, status="500 Internal Server Error")

    # /batch
    if path == "/batch" and method == "POST":
        try:
            filename = sanitize_filename(read_filename(environ))

            if not acquire_lock():
                return response(start_response, status="202 Accepted")

            with open(NFO_FILE, "w") as f:
                f.write(filename)

            cmd = f"{SCANIMAGE} --device-name={DEVICE} --format=jpeg --resolution={RESOLUTION} --buffer-size={BUFFER} --output-file={WORK_DIR}/batch00.jpg"
            run_async(cmd)

            return response(start_response, status="302 Found", headers=[("Location", "batch.html")])
        except:
            return response(start_response, status="500 Internal Server Error")

    # /next
    if path == "/next":

        if os.path.exists(LOCK_FILE):
            if is_lock_stale():
                release_lock()
            return response(start_response, status="202 Accepted")

        files = []
        for i in range(100):
            f = f"{WORK_DIR}/batch{i:02d}.jpg"
            if os.path.exists(f):
                files.append(f)
            else:
                break

        if not files:
            return response(start_response, status="200 OK")

        if not os.path.exists(NFO_FILE):
            for fn in files:
                try:
                    os.remove(fn)
                except:
                    pass
            return response(start_response, status="200 OK")

        if files and os.path.getsize(files[-1]) == 0:
            for fn in files:
                try:
                    os.remove(fn)
                except:
                    pass
            try:
                os.remove(NFO_FILE)
            except:
                pass
            return response(start_response, status="200 OK")

        next_index = len(files)
        output = f"{WORK_DIR}/batch{next_index:02d}.jpg"

        if not acquire_lock():
            return response(start_response, status="202 Accepted")

        cmd = f"{SCANIMAGE} --device-name={DEVICE} --format=jpeg --resolution={RESOLUTION} --buffer-size={BUFFER} --output-file={output}"
        run_async(cmd)

        return response(start_response, status="202 Accepted")

    # /done
    if path == "/done":

        if os.path.exists(LOCK_FILE):
            if is_lock_stale():
                release_lock()
            return response(start_response, status="202 Accepted")

        if os.path.exists(PDF_FILE):
            if os.path.exists(NFO_FILE):
                try:
                    with open(NFO_FILE) as f:
                        name = f.read().strip()
                except:
                    name = ""
                if name:
                    with open(PDF_FILE, "rb") as f:
                        return response(
                            start_response,
                            status="200 OK",
                            body=f.read(),
                            headers=[("Content-Type", "application/pdf"),
                             ("Cache-Control", "no-store"),
                             ("Content-Disposition", f'attachment; filename="{name}.pdf"')]
                        )
            try:
                os.remove(NFO_FILE)
                os.remove(PDF_FILE)
            except:
                pass
            return response(start_response, status="200 OK")

        if not acquire_lock():
            return response(start_response, status="202 Accepted")

        files = sorted([
            f"{WORK_DIR}/batch{i:02d}.jpg"
            for i in range(100)
            if os.path.exists(f"{WORK_DIR}/batch{i:02d}.jpg")
        ])
        cmd = "convert %s %s" % (' '.join(files), PDF_FILE)
        run_async(cmd)

        return response(start_response, status="202 Accepted")

    return response(start_response, status="404 Not Found")


if __name__ == "__main__":
    httpd = make_server(BIND_ADDR, BIND_PORT, app, handler_class=WebScanHandler)
    httpd.serve_forever()
