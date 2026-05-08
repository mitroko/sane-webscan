#!/usr/bin/env python3
"""
Simple Web scanning application based on the SANE/ scaimage
Author: Dzmitry Stremkouski <mitroko@gmail.com>
License: Apache 2.0
Released at: 06.05.2025
"""

# pylint: disable=redefined-builtin
# pylint: disable=consider-using-with
# pylint: disable=too-many-statements
# pylint: disable=too-many-branches
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-locals

import os
import sys
import re
import time
import logging
import subprocess
import unicodedata
import random
import string
import threading
from wsgiref.simple_server import make_server, WSGIRequestHandler

# Configure your own values here
WORK_DIR = os.environ.get("WEBSCAN_WORK_DIR", "/var/lib/sanewebscan")
BIND_ADDR = os.environ.get("WEBSCAN_BIND_ADDR", "127.0.0.1")
BIND_PORT = os.environ.get("WEBSCAN_BIND_PORT", 9080)
LOCK_FILE = os.environ.get("WEBSCAN_LOCK_FILE", f"{WORK_DIR}/lockfile")
LOCK_TTL = os.environ.get("WEBSCAN_LOCK_TTL", 300)
WAIT_TTL = os.environ.get("WEBSCAN_WAIT_TTL", 0)
COOLDOWN = os.environ.get("WEBSCAN_COOLDOWN", 0)
SCANIMAGE = os.environ.get("WEBSCAN_SCANIMAGE", "/usr/bin/scanimage")
DEVICE = os.environ.get("WEBSCAN_DEVICE", "airscan:e0:saneweb")
NFO_FILE = os.environ.get("WEBSCAN_NFO_FILE", f"{WORK_DIR}/filename.nfo")
TOKEN_FILE = os.environ.get("WEBSCAN_TOKEN_FILE", f"{WORK_DIR}/token.file")
JPG_FILE = os.environ.get("WEBSCAN_JPG_FILE", f"{WORK_DIR}/scan.jpg")
PDF_FILE = os.environ.get("WEBSCAN_PDF_FILE", f"{WORK_DIR}/batch.pdf")
RESOLUTION = os.environ.get("WEBSCAN_RESOLUTION", 300)
BUFFER = os.environ.get("WEBSCAN_BUFFER", 512)


logging.basicConfig(
    level=logging.DEBUG,
    format="[%(levelname)s]: %(message)s"
)
logger = logging.getLogger("SANE Web Scan")


class WebScanHandler(WSGIRequestHandler):
    """Own class to handle X-Proxy headers for logging"""

    def address_string(self):
        """Calculate address_string"""
        forwarded = self.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return self.client_address[0]

    def log_message(self, format, *args):
        """Calculate client_ip and drop the log line"""
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
    """Check the filename and replace ambiguos chars"""
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
    """Simple lock acquiring function based on a file"""
    logger.debug("Creating lock file %s", LOCK_FILE)
    try:
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        time.sleep(1)
        return True
    except FileExistsError:
        logger.debug("Lock file was not created")
        return False

def is_lock_stale():
    """Stale lock checker"""
    try:
        return (time.time() - os.path.getmtime(LOCK_FILE)) > LOCK_TTL
    except IOError:
        return False

def response(start_response, status="200 OK", body=b"", headers=None):
    """Return the data to a client"""
    if headers is None:
        headers = []
    start_response(status, headers)
    return [body]

def read_token(environ):
    """Get the filename cookie from the environment of the wsgi application"""
    try:
        size = int(environ.get("CONTENT_LENGTH", 0))
        data = environ["wsgi.input"].read(size).decode()
        for part in data.split("&"):
            if part.startswith("cleaner_token="):
                return part.split("=")[1] or ""
    except KeyError:
        pass
    return ""

def read_filename(environ):
    """Get the filename from the environment of the wsgi application"""
    try:
        size = int(environ.get("CONTENT_LENGTH", 0))
        data = environ["wsgi.input"].read(size).decode()
        for part in data.split("&"):
            if part.startswith("filename="):
                return part.split("=")[1] or "scan"
    except KeyError:
        pass
    return "scan"


def run_blocking(cmd):
    """Perform blocking process call. Wait until it finishes"""
    logger.debug("Executing: %s", cmd)
    try:
        with subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True
        ) as proc:
            logger.debug("Blocking call executed")
    except ChildProcessError as e:
        logger.debug("Blocking call exception: %s", e)
        safe_remove(LOCK_FILE, "lock file")

    try:
        logger.debug("Proc communication started")
        stdout, stderr = proc.communicate()
        if proc.returncode == 0:
            logger.debug("Subprocess call [stdout]: %s", stdout.decode("utf-8"))
            safe_remove(LOCK_FILE, "lock file")
            logger.debug("Exit code 0 lock released")
        else:
            logger.debug("Subprocess call [stderr]: %s lock released", stderr.decode("utf-8"))
            safe_remove(LOCK_FILE, "lock file")
    except BrokenPipeError as e:
        logger.debug("Blocking call exception: %s", e)

def worker_thread(cmd_list):
    try:
        subprocess.run(
            cmd_list,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )

        logger.debug("Scanning complete, Cooldown %s seconds", COOLDOWN)
        time.sleep(float(COOLDOWN))

    except subprocess.CalledProcessError as e:
        logger.exception("scanimage failed: %s", e)
    finally:
        safe_remove(LOCK_FILE, "lock file")

def run_async(cmd):
    """Perform asynchronous process call. Fire and forget"""
    logger.debug("Executing: %s", cmd)
    t = threading.Thread(
        target=worker_thread,
        args=(cmd.split(),),
        daemon=True
    )

    t.start()

def safe_remove(fp, comment=""):
    """Check if file exists and remove it"""

    if len(comment) > 0:
        to_log = comment
    else:
        to_log = str(fp)

    if os.path.exists(fp):
        logger.debug("%s exists - removing", to_log)
        try:
            os.remove(fp)
        except IOError:
            logger.debug("Can not remove %s", to_log)

def app(environ, start_response):
    """Main app itself for managing scan requests"""
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD")
    # client = environ.get("HTTP_X_FORWARDED_FOR")

    # logger.debug("Environment: {}".format(environ))
    # logger.debug("uwsgi client: {}".format(client))
    # logger.debug("uwsgi path call: {}".format(path))
    # logger.debug("uwsgi call method: {}".format(method))

    # /healthz
    if path == "/healthz":
        return response(start_response, status="200 OK")

    # /cleanup
    if path == "/cleanup" and method == "POST":
        logger.debug("/cleanup API call triggered")
        try:
            logger.debug("Reading token from the client")
            cleaner_token = read_token(environ)

            if len(cleaner_token) == 0:
                logger.debug("No token or 0 size token sent")
                return response(start_response, status="401 Unauthorized")

            logger.debug("Reading token from the file")
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                token = f.read().strip()

            if not cleaner_token == token:
                logger.debug("Improper token sent, rejecting")
                return response(start_response, status="401 Unauthorized")

            logger.debug("Cleanup token accepted, removing files")
            safe_remove(TOKEN_FILE, "token file")
            safe_remove(NFO_FILE, "nfo file")
            safe_remove(JPG_FILE, "jpg file")
            safe_remove(PDF_FILE, "pdf file")
            return response(start_response, status="302 Found", headers=[("Location", \
                "index.html")])
        except RuntimeError:
            return response(start_response, status="500 Internal Server Error")

    # /poll
    if path == "/poll":

        logger.debug("/poll API call triggered")
        if os.path.exists(LOCK_FILE):
            logger.debug("Lock file is in place")
            if is_lock_stale():
                logger.debug("Lock file is stale, releasing")
                safe_remove(LOCK_FILE, "lock file")
            return response(start_response, status="202 Accepted")

        if os.path.exists(JPG_FILE) and os.path.exists(NFO_FILE):
            logger.debug("jpg file is in place and its info file")
            if os.path.getsize(JPG_FILE) > 0:
                logger.debug("jpg file has proper size")
                try:
                    logger.debug("reading filename from nfo")
                    with open(NFO_FILE, encoding="utf-8") as f:
                        name = f.read().strip()
                except IOError:
                    logger.debug("invalid filename replaced with ''")
                    name = ""
                try:
                    logger.debug("reading token file")
                    with open(TOKEN_FILE, encoding="utf-8") as f:
                        token = f.read().strip()
                except IOError:
                    logger.debug("Cannot read token from file")
                    token = ""
                if name and token:
                    logger.debug("file is returned to a client")
                    with open(JPG_FILE, "rb") as f:
                        return response(
                            start_response,
                            status="200 OK",
                            body=f.read(),
                            headers=[("Content-Type", "image/jpeg"),
                             ("Cache-Control", "no-store"),
                             ("X-Cleanup-Cookie", token),
                             ("Content-Disposition", f'attachment; filename="{name}.jpg"')]
                        )
            logger.debug("file not returned to a client, probably broken")
            return response(start_response, status="302 Found", headers=[("Location", \
                "index.html")])

        if os.path.exists(PDF_FILE) and os.path.exists(NFO_FILE):
            logger.debug("pdf file is in place and its info file")
            if os.path.getsize(PDF_FILE) > 0:
                logger.debug("pdf file has proper size")
                try:
                    logger.debug("reading filename from nfo")
                    with open(NFO_FILE, encoding="utf-8") as f:
                        name = f.read().strip()
                except IOError:
                    logger.debug("invalid filename replaced with ''")
                    name = ""
                try:
                    logger.debug("reading token file")
                    with open(TOKEN_FILE, encoding="utf-8") as f:
                        token = f.read().strip()
                except IOError:
                    logger.debug("Cannot read token from file")
                    token = ""
                if name and token:
                    logger.debug("file is returned to a client")
                    with open(PDF_FILE, "rb") as f:
                        return response(
                            start_response,
                            status="200 OK",
                            body=f.read(),
                            headers=[("Content-Type", "application/pdf"),
                             ("Cache-Control", "no-store"),
                             ("X-Cleanup-Cookie", token),
                             ("Content-Disposition", f'attachment; filename="{name}.pdf"')]
                        )
            logger.debug("file not returned to a client, probably broken")
            return response(start_response, status="302 Found", headers=[("Location", \
                "index.html")])

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
            if (time.time() - os.path.getmtime(NFO_FILE)) > float(WAIT_TTL):
                logger.debug("Failover cleanup phase")
                safe_remove(TOKEN_FILE, "token file")
                safe_remove(NFO_FILE, "nfo file")
                safe_remove(JPG_FILE, "jpg file")
                safe_remove(PDF_FILE, "pdf file")
                for i in range(100):
                    cur_file = f"{WORK_DIR}/batch{i:02d}.jpg"
                    if os.path.exists(cur_file):
                        safe_remove(cur_file, "")

                logger.debug("Cleanup phase completed")
        return response(start_response, status="200 OK")

    # /scan
    if path == "/scan" and method == "POST":
        logger.debug("/scan API call triggered")
        try:
            filename = sanitize_filename(read_filename(environ))

            if not acquire_lock():
                logger.debug("/scan lock not acquired, try again")
                safe_remove(LOCK_FILE, "lock file")
                return response(start_response, status="302 Found", headers=[("Location", \
                    "index.html")])

            with open(NFO_FILE, "w", encoding="utf-8") as f:
                f.write(filename)
            logger.debug("/scan filename.nfo created")

            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                alphabet = string.ascii_letters + string.digits
                token = ''.join(random.choice(alphabet) for _ in range(32))
                f.write(token)
            logger.debug("/scan token.file created")

            cmd = f"{SCANIMAGE} --device-name={DEVICE} --format=jpeg --resolution={RESOLUTION} \
                --buffer-size={BUFFER} --output-file={JPG_FILE}"
            logger.debug("/scan call: %s", cmd)
            run_async(cmd)

            return response(start_response, status="302 Found", headers=[("Location", "scan.html")])
        except RuntimeError as e:
            logger.debug("/scan failed: %s", e)
            return response(start_response, status="500 Internal Server Error")

    # /batch
    if path == "/batch" and method == "POST":
        logger.debug("/batch API call triggered")
        try:
            filename = sanitize_filename(read_filename(environ))

            if not acquire_lock():
                logger.debug("/batch lock not acquired, try again")
                safe_remove(LOCK_FILE, "lock file")
                return response(start_response, status="302 Found", headers=[("Location", \
                    "index.html")])

            with open(NFO_FILE, "w", encoding="utf-8") as f:
                f.write(filename)
            logger.debug("/batch filename.nfo created")

            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                alphabet = string.ascii_letters + string.digits
                token = ''.join(random.choice(alphabet) for _ in range(32))
                f.write(token)
            logger.debug("/batch token.file created")

            files = []
            for i in range(100):
                f = f"{WORK_DIR}/batch{i:02d}.jpg"
                if os.path.exists(f):
                    safe_remove(f)

            cmd = f"{SCANIMAGE} --device-name={DEVICE} --format=jpeg --resolution={RESOLUTION} \
                --buffer-size={BUFFER} --output-file={WORK_DIR}/batch00.jpg"
            run_async(cmd)

            return response(start_response, status="302 Found", headers=[("Location", \
                "batch.html")])
        except RuntimeError:
            return response(start_response, status="500 Internal Server Error")

    # /next
    if path == "/next":

        logger.debug("/next API call triggered")
        if os.path.exists(LOCK_FILE):
            if is_lock_stale():
                safe_remove(LOCK_FILE, "lock file")
                return response(start_response, status="302 Found", headers=[("Location", \
                    "index.html")])
            return response(start_response, status="302 Found", headers=[("Location", \
                "batch.html")])

        files = []
        for i in range(100):
            f = f"{WORK_DIR}/batch{i:02d}.jpg"
            if os.path.exists(f):
                files.append(f)
            else:
                break

        if not files:
            safe_remove(LOCK_FILE, "lock file")
            return response(start_response, status="302 Found", headers=[("Location", \
                "index.html")])

        if not os.path.exists(NFO_FILE):
            for fn in files:
                safe_remove(fn)
            return response(start_response, status="302 Found", headers=[("Location", \
                "index.html")])

        if files and os.path.getsize(files[-1]) == 0:
            for fn in files:
                safe_remove(fn)
            safe_remove(NFO_FILE, "nfo file")
            return response(start_response, status="302 Found", headers=[("Location", \
                "index.html")])

        if not acquire_lock():
            logger.debug("/next lock not acquired, try again")
            safe_remove(LOCK_FILE, "lock file")
            for fn in files:
                safe_remove(fn)
            safe_remove(NFO_FILE, "nfo file")
            return response(start_response, status="302 Found", headers=[("Location", \
                "index.html")])

        next_index = len(files)
        output = f"{WORK_DIR}/batch{next_index:02d}.jpg"

        cmd = f"{SCANIMAGE} --device-name={DEVICE} --format=jpeg --resolution={RESOLUTION} \
            --buffer-size={BUFFER} --output-file={output}"
        run_async(cmd)

        return response(start_response, status="302 Found", headers=[("Location", \
            "batch.html")])

    # /done
    if path == "/done":

        logger.debug("/done API call triggered")
        if not acquire_lock():
            return response(start_response, status="302 Found", headers=[("Location", \
                "index.html")])

        files = sorted([
            f"{WORK_DIR}/batch{i:02d}.jpg"
            for i in range(100)
            if os.path.exists(f"{WORK_DIR}/batch{i:02d}.jpg")
        ])

        file_names = ' '.join(files)
        cmd = f"convert {file_names} {PDF_FILE}"
        run_blocking(cmd)

        for fn in files:
            safe_remove(fn)

        return response(start_response, status="302 Found", headers=[("Location", \
            "batch.html")])

    return response(start_response, status="404 Not Found")


if __name__ == "__main__":
    httpd = make_server(BIND_ADDR, BIND_PORT, app, handler_class=WebScanHandler)
    httpd.serve_forever()
