from quart import Quart
import subprocess
from hypercorn.config import Config
from hypercorn.asyncio import serve
import asyncio
import os

app = Quart(__name__)
CERT_DIR = ("./outcert")
import os
os.environ["SSLKEYLOGFILE"] = "/tmp/sslkeys.log"

@app.route('/')
async def index():
    return "HTTP/2 Server is Running!"


def getip() -> str:
    cmd = "ifconfig | grep -w 'inet' | grep -v '127.0.0.1'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    lan_ip = result.stdout.strip().split()[1]
    return lan_ip


if __name__ == "__main__":
    config = Config()

    ip = "127.0.0.1"
    port = "8443"
    config.bind = [f"127.0.0.1:{port}"]

    config.certfile = os.path.join(CERT_DIR, "cert.pem")
    config.keyfile = os.path.join(CERT_DIR, "key.pem")

    print(f"Targeting IP: {ip} on Port: {port}")
    print(f"Firewall testing active. Listening for H2 traffic...")

    try:
        asyncio.run(serve(app, config))
    except Exception as e:
        print(f"Server failed to start: {e}")
