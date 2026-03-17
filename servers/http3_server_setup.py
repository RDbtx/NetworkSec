import asyncio
import os
import subprocess
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration

CERT_DIR = ("./outcert")


def getip() -> str:
    cmd = "ifconfig | grep -w 'inet' | grep -v '127.0.0.1'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    lan_ip = result.stdout.strip().split()[1]
    return lan_ip


async def main():
    configuration = QuicConfiguration(
        is_client=False,
    )
    # Correct way to load certificates in aioquic
    configuration.load_cert_chain(
        os.path.join(CERT_DIR, "cert.pem"),
        os.path.join(CERT_DIR, "key.pem")
    )

    ip = getip()
    port = 4433 # Changed from 433 to avoid sudo issues

    print(f"Starting HTTP/3 (QUIC) Server on {ip}:{port}...")
    await serve(
        ip,
        port,
        configuration=configuration,
    )
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
