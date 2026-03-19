"""
data_extraction.py
==================
Live network traffic capture and feature extraction for the Blackwall firewall.

Captures packets from a live interface using tshark and places each packet
on a queue as a (source_ip, raw_df) tuple for firewall_engine.py to consume.
Preprocessing (fill_missing → resolve_compound → OHE → MinMax scale) is
handled by LivePreprocessor inside firewall_engine.py.

Extraction method mirrors dataset_regenerator.py exactly:
  - separator  : "|"   (ASCII pipe — safe on all platforms)
  - occurrence : "a"   (emit ALL occurrences of repeated fields per packet)
  - quote      : "d"   (double-quote wrapping, stripped in post-processing)
  - fields     : validated against `tshark -G fields` before each run

Post-processing (three ordered steps — order is mandatory):
  1. "," → "+"    multi-value commas inside fields → summable strings
  2. strip "      remove -E quote=d wrapping
  3. "|" → ","    pipe separator → standard CSV comma  (MUST be last)

Queue contract (consumed by firewall_engine.py):
    source_ip, raw_df = capture.queue.get(timeout=0.5)

    source_ip : str | None   — ip.src or ipv6.src value from the packet
    raw_df    : pd.DataFrame — single-row DataFrame with the 46 FEATURES
                               columns, raw unpreprocessed string values.
                               Fed into LivePreprocessor.preprocess() in
                               firewall_engine.py before model inference.
"""

import os
import platform
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Optional
import pandas as pd

# ── 46 model features (no Label) ─────────────────────────────────────────────
FEATURES = [
    "frame.len", "ip.len", "tcp.len", "tcp.hdr_len", "tcp.flags.ack",
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
    "http.content_length", "http.content_type",
]

# ── tshark settings ───────────────────────────────────────────────────────────
_SEP = "|"
_DEFAULT_KEYLOG = "/tmp/sslkeys.log"


# ═══════════════════════════════════════════════════════════════════════════════
#   tshark helpers  (identical to dataset_regenerator.py)
# ═══════════════════════════════════════════════════════════════════════════════

def _find_tshark() -> str:
    """
    Auto-detect the tshark binary. Checks the TSHARK environment variable
    first, then PATH, then common install locations.
    """
    env = os.environ.get("TSHARK")
    if env:
        return env
    cmd = "where" if sys.platform == "win32" else "which"
    try:
        r = subprocess.run([cmd, "tshark"], capture_output=True, text=True)
        found = r.stdout.strip().splitlines()
        if found:
            return found[0]
    except FileNotFoundError:
        pass
    for p in ("/usr/bin/tshark", "/usr/local/bin/tshark",
              r"C:\Program Files\Wireshark\tshark.exe"):
        if Path(p).exists():
            return p
    raise FileNotFoundError(
        "tshark not found. Install Wireshark/tshark or set the TSHARK env variable."
    )


def _get_supported_fields(tshark: str) -> set[str]:
    """
    Query tshark for its full field registry and return the set of supported
    field names. Used to skip FEATURES entries the installed tshark version
    does not recognise.
    """
    proc = subprocess.run(
        [tshark, "-G", "fields"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    supported: set[str] = set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            supported.add(parts[2].strip())
    return supported


def _postprocess_line(raw: str) -> str:
    """
    Three-step H23Q post-processing pipeline. Order is mandatory.

      1. "," → "+"    multi-value commas → summable strings
      2. strip "      remove -E quote=d wrapping
      3. "|" → ","    pipe separator → standard CSV comma  (MUST be last)
    """
    result = raw.replace(",", "+")
    result = result.replace('"', "")
    result = result.replace(_SEP, ",")
    return result


def _parse_row(
        header_cols: list[str],
        processed_line: str,
        valid_features: list[str],
) -> dict[str, Any]:
    """
    Split one post-processed CSV line and return a dict keyed by FEATURES.
    Missing or empty values become None.
    Features unsupported by this tshark version are always None.
    """
    parts = processed_line.split(",")
    while len(parts) < len(header_cols):
        parts.append("")
    row_raw = dict(zip(header_cols, parts))

    row: dict[str, Any] = {}
    for feat in FEATURES:
        if feat in valid_features:
            val = row_raw.get(feat, "").strip()
            row[feat] = val if val else None
        else:
            row[feat] = None
    return row


def _extract_source_ip(header_cols: list[str], raw_line: str) -> str | None:
    """
    Extract ip.src or ipv6.src from the raw (pre-postprocess) tshark line.
    Must be called before _postprocess_line — comma→plus would corrupt IPs.
    ip.src and ipv6.src are appended after FEATURES in the tshark command.
    """
    parts_raw = raw_line.replace('"', "").split(_SEP)
    row_raw = dict(zip(header_cols, parts_raw))
    ip = row_raw.get("ip.src") or row_raw.get("ipv6.src")
    if ip:
        ip = ip.strip()
    return ip if ip else None


# ═══════════════════════════════════════════════════════════════════════════════
#   LiveCapture
# ═══════════════════════════════════════════════════════════════════════════════

class LiveCapture:
    """
    Captures live packets from a network interface using tshark, applies the
    full scaling.py preprocessing pipeline to each packet, and places the
    preprocessed result on a queue for firewall_engine.py to consume.

    Queue items
    -----------
    Each item on self.queue is a tuple:
        (source_ip: str | None, preprocessed_df: pd.DataFrame)

        source_ip       : ip.src or ipv6.src string, or None
        preprocessed_df : single-row DataFrame, fully scaled and OHE-encoded,
                          ready for model.predict() — no further preprocessing
                          required in firewall_engine.py

    Parameters
    ----------
    interface   : network interface name (e.g. "eth0", "en0", "Wi-Fi")
    bpf_filter  : optional BPF capture filter (e.g. "dst host 10.0.0.1")
    keylog_file : path to an NSS SSLKEYLOGFILE for live TLS decryption.
                  Defaults to /tmp/sslkeys.log.
    tshark_bin  : explicit tshark binary path (auto-detected if None)
    """

    def __init__(
            self,
            interface: str,
            bpf_filter: Optional[str] = None,
            keylog_file: Optional[str] = None,
            tshark_bin: Optional[str] = None,
    ) -> None:
        if interface is None:
            interface = "eth0" if platform.system() in ("Windows", "Linux") else "en0"

        self.interface = interface
        self.bpf_filter = bpf_filter
        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

        # Resolve tshark binary and validate feature list once at init time
        self._tshark = tshark_bin or _find_tshark()
        supported = _get_supported_fields(self._tshark)
        self._valid_features = [f for f in FEATURES if f in supported]
        invalid = [f for f in FEATURES if f not in supported]
        if invalid:
            print(f"[LiveCapture] WARN: {len(invalid)} unsupported fields "
                  f"will be NULL: {invalid}")

        # Resolve keylog — create file if missing so tshark does not error
        self.keylog_file = keylog_file or _DEFAULT_KEYLOG
        if not os.path.exists(self.keylog_file):
            open(self.keylog_file, "a").close()
        os.environ["SSLKEYLOGFILE"] = self.keylog_file

    # ── internal ──────────────────────────────────────────────────────────────

    def _build_cmd(self) -> list[str]:
        cmd = [
            self._tshark,
            "-i", self.interface,
            "-l",  # line-buffered — critical for streaming
            "-T", "fields",
            "-E", f"separator={_SEP}",
            "-E", "header=y",
            "-E", "quote=d",
            "-E", "occurrence=a",  # mirrors dataset_regenerator.py
        ]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        cmd += ["-o", f"tls.keylog_file:{self.keylog_file}"]
        for feat in self._valid_features:
            cmd += ["-e", feat]
        # ip.src / ipv6.src appended after model features for source IP
        # tracking — never included in the DataFrame passed to the model
        cmd += ["-e", "ip.src", "-e", "ipv6.src"]
        return cmd

    def _capture_loop(self) -> None:
        cmd = self._build_cmd()
        print(f"[LiveCapture] interface  = {self.interface}")
        print(f"[LiveCapture] keylog     = {self.keylog_file}")
        print(f"[LiveCapture] tshark     = {self._tshark}")
        if self.bpf_filter:
            print(f"[LiveCapture] bpf_filter = {self.bpf_filter}")
        print(f"[LiveCapture] features   = "
              f"{len(self._valid_features)} / {len(FEATURES)} supported")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        header_cols: list[str] = []
        seen = 0
        errors = 0

        try:
            for raw_line in proc.stdout:
                if self.stop_event.is_set():
                    break

                raw_line = raw_line.rstrip("\n")
                if not raw_line:
                    continue

                # ── first non-empty line is the tshark field header ────────
                if not header_cols:
                    clean_header = raw_line.replace('"', "").replace(_SEP, ",")
                    header_cols = [c.strip() for c in clean_header.split(",")]
                    print(f"[LiveCapture] tshark started: "
                          f"{len(header_cols)} columns")
                    continue

                # ── extract source IP before postprocessing ────────────────
                # Must happen on the raw line — comma→plus corrupts IP strings
                source_ip = _extract_source_ip(header_cols, raw_line)

                # ── postprocess → parse → build raw DataFrame → enqueue ───
                try:
                    processed = _postprocess_line(raw_line)
                    row = _parse_row(header_cols, processed,
                                     self._valid_features)
                    raw_df = pd.DataFrame([row], columns=FEATURES)
                    self.queue.put((source_ip, raw_df))
                    seen += 1
                except Exception as exc:
                    errors += 1
                    if errors <= 10:
                        print(f"[LiveCapture] error (pkt {seen + errors}): {exc}")

        except Exception as exc:
            print(f"[LiveCapture] fatal loop error: {exc}")

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            stderr_out = proc.stderr.read() if proc.stderr else ""
            if stderr_out.strip():
                lines = stderr_out.strip().splitlines()
                print(f"[LiveCapture] tshark warnings "
                      f"({len(lines)} lines, first 5):")
                for line in lines[:5]:
                    print(f"    {line}")
            print(f"[LiveCapture] stopped — packets={seen}, errors={errors}")

    # ── public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start live capture in a background daemon thread."""
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        print(f"[LiveCapture] capture thread started on [{self.interface}]")

    def stop(self) -> None:
        """Signal the capture loop to stop and wait for the thread to finish."""
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=10)
        print("[LiveCapture] stopped.")
