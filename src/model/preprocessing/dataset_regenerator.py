import csv
import os
import pathlib
import subprocess
import sys
from pathlib import Path
from typing import Any

MODEL_DIR = pathlib.Path(__file__).parent.parent
OUTPUT_FOLDER = os.path.join(MODEL_DIR, "new_dataset")
DATASET_FOLDER = os.path.join(MODEL_DIR, "dataset")
SSLKEYS = os.path.join(MODEL_DIR, "dataset/ssl keys/all.txt")

PREFILTERING_FEATURES = [
    "frame.len", "frame.time_relative", "ip.len", "ip.src", "ip.dst", "tcp.len", "tcp.hdr_len", "tcp.flags.ack",
    "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin",
    "tcp.window_size_value", "tcp.option_len", "udp.length", "tls.record.length",
    "tls.reassembled.length", "tls.handshake.length", "tls.handshake.certificates_length",
    "tls.handshake.certificate_length", "tls.handshake.session_id_length",
    "tls.handshake.cipher_suites_length", "tls.handshake.extensions_length",
    "tls.handshake.client_cert_vrfy.sig_len", "quic.packet_length", "quic.long.packet_type",
    "quic.packet_number_length", "quic.length", "quic.nci.connection_id.length",
    "quic.crypto.length", "quic.fixed_bit", "quic.spin_bit", "quic.stream.fin",
    "quic.stream.len", "quic.token_length", "quic.padding_length", "http2.length",
    "http2.header.length", "http2.header.name.length", "http2.header.value.length",
    "http2.headers.content_length", "http3.frame_length",
    "http3.settings.qpack.max_table_capacity", "http3.settings.max_field_section_size",
    "dns.flags.response", "dns.count.queries", "dns.count.answers",
    "http.content_length", "http.content_type", "http.host", "udp.dstport", "dns.id", "urlencoded-form.key"
]

MULTI_VALUE_FEATURES = {
    "tcp.option_len",
    "tls.record.length",
    "tls.handshake.length",
    "tls.handshake.certificate_length",
    "tls.handshake.extensions_length",
    "http2.length",
    "http2.header.name.length",
    "http2.header.value.length",
}

_BINARY_FLAG_COLS = {
    "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset",
    "tcp.flags.syn", "tcp.flags.fin",
    "quic.fixed_bit", "quic.spin_bit", "quic.stream.fin",
    "dns.flags.response",
}

_SEP = "|"


def _find_tshark() -> str:
    cmd = "where" if sys.platform == "win32" else "which"
    try:
        r = subprocess.run([cmd, "tshark"], capture_output=True, text=True)
        found = r.stdout.strip().splitlines()
        if found:
            return found[0]
    except FileNotFoundError:
        pass

    for p in (
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            r"C:\Program Files\Wireshark\tshark.exe",
    ):
        if Path(p).exists():
            return p

    raise FileNotFoundError("tshark not found. Install Wireshark/tshark.")


def _get_supported_fields(tshark: str) -> set[str]:
    proc = subprocess.run(
        [tshark, "-G", "fields"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
        check=True,
    )

    supported = set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            supported.add(parts[2].strip())
    return supported


def _postprocess(raw: str) -> str:
    result = raw.replace(",", "+")
    result = result.replace('"', "")
    result = result.replace(_SEP, ",")
    return result


def extract_tshark_packets(
        pcap: str,
        keylog: str | None = None,
        n: int | None = None,
) -> list[tuple[dict[str, Any], list[str]]]:
    tshark = _find_tshark()
    supported = _get_supported_fields(tshark)

    valid_features = [f for f in PREFILTERING_FEATURES if f in supported]
    invalid_features = [f for f in PREFILTERING_FEATURES if f not in supported]

    if invalid_features:
        print("[!] Unsupported features skipped:")
        for f in invalid_features:
            print(f"    - {f}")

    cmd = [
        tshark, "-r", pcap, "-T", "fields",
        "-E", f"separator={_SEP}",
        "-E", "header=y",
        "-E", "quote=d",
        "-E", "occurrence=a",
    ]

    if keylog and Path(keylog).exists():
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    else:
        print("[!] WARN: keylog not found — TLS fields may be empty")

    for feat in valid_features:
        cmd += ["-e", feat]

    print(f">>> Running tshark on {Path(pcap).name} ...")
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    )

    if proc.returncode != 0:
        for line in proc.stderr.strip().splitlines()[:10]:
            print(f"    {line}")
        raise RuntimeError(f"tshark exited with code {proc.returncode}")

    stderr_lines = proc.stderr.strip().splitlines() if proc.stderr.strip() else []
    if stderr_lines:
        print(f"[!] tshark warnings ({len(stderr_lines)} lines, first 5):")
        for line in stderr_lines[:5]:
            print(f"    {line}")

    clean = _postprocess(proc.stdout)
    lines = clean.strip().splitlines()

    if len(lines) < 2:
        for line in proc.stdout.splitlines()[:3]:
            print(f"    RAW: {repr(line)}")
        raise RuntimeError("tshark produced no data rows after post-processing.")

    header = [c.strip() for c in lines[0].split(",")]

    limit = n if n is not None else len(lines) - 1
    results: list[tuple[dict[str, Any], list[str]]] = []

    for line in lines[1: limit + 1]:
        parts = line.split(",")
        while len(parts) < len(header):
            parts.append("")

        row_raw = dict(zip(header, parts))

        row: dict[str, Any] = {}
        for feat in PREFILTERING_FEATURES:
            val = row_raw.get(feat, "").strip()
            row[feat] = val if val else None

        results.append((row, ["tshark"]))

    return results


def extract_to_csv(pcap_path: str, output_csv: str, keylog: str):
    rows = extract_tshark_packets(pcap_path, keylog=keylog)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(PREFILTERING_FEATURES)

        for row, _ in rows:
            writer.writerow([row.get(feat, None) for feat in PREFILTERING_FEATURES])

    print(f"    CSV written to: {output_csv}")


def dataset_regenerator():
    for folder in os.listdir(DATASET_FOLDER):
        folder_path = os.path.join(DATASET_FOLDER, folder)
        if not os.path.isdir(folder_path):
            continue

        for file in os.listdir(folder_path):
            if file.endswith(".pcap"):
                pcap_path = os.path.join(folder_path, file)
                out_name = os.path.join(folder, f"{Path(file).stem}.csv")
                extract_to_csv(
                    pcap_path,
                    os.path.join(OUTPUT_FOLDER, out_name),
                    keylog=SSLKEYS,
                )
