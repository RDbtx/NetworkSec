"""
data_extraction.py
==================
Live traffic capture and feature extraction using tshark directly.
No pyshark — tshark is invoked as a subprocess on the network interface,
its stdout is read line-by-line, and each row is parsed, preprocessed,
and pushed to a queue for the firewall/classifier to consume.

Architecture
------------
  LiveCapture.start()
      └─ background thread runs _capture_loop()
             └─ spawns:  tshark -i <iface> -T fields -E separator=| ...
             └─ reads stdout line by line
             └─ for each complete row: parse → preprocess → queue.put()

  Consumer (firewall):
      src_ip, preprocessed_df = capture.queue.get()

TLS decryption
--------------
  Pass keylog_file pointing to an NSS SSLKEYLOGFILE (all.txt equivalent).
  tshark will decrypt TLS on-the-fly, exposing HTTP/2, HTTP/3, and QUIC
  application-layer fields — identical to how the training data was captured.
"""

from __future__ import annotations

import os
import platform
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd

from src.model.preprocessing.filtering import FEATURES
from src.model.preprocessing.scaling import FLAG_COLS, TO_SCALE_COLUMNS

# ── model features (no Label) ─────────────────────────────────────────────────
MODEL_FEATURES: list[str] = [f for f in FEATURES if f != "Label"]

# ── separator — ASCII pipe, never appears in any network field value ──────────
_SEP = "|"

# ── default keylog path ───────────────────────────────────────────────────────
_DEFAULT_KEYLOG = "/tmp/sslkeys.log"


# ═══════════════════════════════════════════════════════════════════════════════
#   tshark utilities
# ═══════════════════════════════════════════════════════════════════════════════

def find_tshark() -> str:
    """Auto-detect tshark binary. Raises FileNotFoundError if not found."""
    env = os.environ.get("TSHARK")
    if env:
        return env
    cmd = "where" if sys.platform == "win32" else "which"
    try:
        result = subprocess.run([cmd, "tshark"], capture_output=True, text=True)
        found = result.stdout.strip().splitlines()
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


def postprocess_row(raw_line: str) -> str:
    """
    Apply the UltraEdit post-processing steps from the dataset README:
      1. "," → "+"   multi-value field commas become summable arithmetic strings
      2. strip "     remove -E quote=d wrapping
      3. "|" → ","   our column separator becomes a standard CSV comma
    Order is mandatory: step 3 must be last.
    """
    result = raw_line.replace(",", "+")
    result = result.replace('"', "")
    result = result.replace(_SEP, ",")
    return result


def parse_row(header_cols: list[str], processed_line: str) -> dict[str, str | None]:
    """
    Split one post-processed CSV data line and return a dict of
    {feature_name: raw_string_value | None} for MODEL_FEATURES only.
    """
    parts = processed_line.split(",")
    while len(parts) < len(header_cols):
        parts.append("")
    raw = dict(zip(header_cols, parts))
    return {feat: (raw.get(feat, "").strip() or None) for feat in MODEL_FEATURES}


def row_to_dataframe(row: dict[str, str | None]) -> pd.DataFrame:
    """Wrap a feature dict in a single-row DataFrame."""
    return pd.DataFrame([row], columns=MODEL_FEATURES)


# ═══════════════════════════════════════════════════════════════════════════════
#   Preprocessor  (mirrors scaling.py exactly)
# ═══════════════════════════════════════════════════════════════════════════════

class LivePreprocessor:
    """
    Applies the four scaling.py steps to a single-row DataFrame from the live
    capture pipeline so it is aligned to the feature space the model expects.

    Load once at startup; call preprocess(df) for every incoming packet.

    Parameters
    ----------
    dataset_csv   : path to pcap-all-final.csv  (header used for OHE alignment)
    scaler_joblib : path to scaler.joblib saved during training
    """

    def __init__(self, dataset_csv: str | Path, scaler_joblib: str | Path) -> None:
        saved = joblib.load(scaler_joblib)
        if isinstance(saved, dict):
            self.scaler = saved["scaler"]
            self.scaler_columns: list[str] = saved.get("scaler_columns", TO_SCALE_COLUMNS)
        else:
            self.scaler = saved
            self.scaler_columns = TO_SCALE_COLUMNS

        header_df = pd.read_csv(dataset_csv, nrows=0)
        self.ohe_columns: list[str] = [c for c in header_df.columns if c != "Label"]

    def fill_missing(self, df: pd.DataFrame) -> pd.DataFrame:
        """FLAG_COLS NaN → -1 (distinct OHE category); all else → 0."""
        for col in FLAG_COLS:
            if col in df.columns:
                df[col] = df[col].fillna(-1)
        return df.fillna(0)

    def resolve_compound(self, df: pd.DataFrame) -> pd.DataFrame:
        """Evaluate arithmetic strings like "3+8+5+1" → 17.0."""
        obj_cols = [c for c in df.select_dtypes(include=["object", "string"]).columns
                    if c != "Label"]
        for col in obj_cols:
            def _safe_eval(v, _c=col):
                if not isinstance(v, str):
                    return v
                if not any(op in v for op in ("+", "-", "*", "/")):
                    return v
                try:
                    return pd.eval(str(v))
                except Exception:
                    return v

            df[col] = df[col].apply(_safe_eval)
        return df

    def ohe(self, df: pd.DataFrame) -> pd.DataFrame:
        """OHE FLAG_COLS then reindex to exact training column set."""
        present = [c for c in FLAG_COLS if c in df.columns]
        for col in present:
            df[col] = df[col].astype(str)
        df = pd.get_dummies(df, columns=present)
        return df.reindex(columns=self.ohe_columns, fill_value=0)

    def scale(self, df: pd.DataFrame) -> pd.DataFrame:
        """MinMax-scale numeric columns using the fitted training scaler."""
        cols = [c for c in self.scaler_columns if c in df.columns]
        df[cols] = pd.to_numeric(df[cols].stack(), errors="coerce").unstack().fillna(0)
        df[cols] = df[cols].astype(float)
        df[cols] = self.scaler.transform(df[cols])
        return df

    def preprocess(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df = self.fill_missing(df)
        df = self.resolve_compound(df)
        df = self.ohe(df)
        df = self.scale(df)
        return df


# ═══════════════════════════════════════════════════════════════════════════════
#   FileCapture  — offline / PCAP-file iterator
# ═══════════════════════════════════════════════════════════════════════════════

class FileCapture:
    """
    Iterates over packets in a PCAP file using tshark (-r), yielding one
    (source_ip, raw_df) tuple per packet — identical format to LiveCapture's
    queue items, but synchronous and file-based.

    Designed to be used directly in a for-loop:

        for source_ip, df in FileCapture("capture.pcap", keylog="all.txt"):
            processed = preprocessor.preprocess(df)
            label = model.predict(processed.values.astype(float))

    Parameters
    ----------
    pcap_path  : path to the input PCAP file
    keylog     : path to NSS SSLKEYLOGFILE for TLS decryption (all.txt)
    tshark_bin : explicit tshark path (auto-detected if None)

    Yields
    ------
    (source_ip: str | None, raw_df: pd.DataFrame)
        source_ip : ip.src or ipv6.src string, or None if not present
        raw_df    : single-row DataFrame with raw (unpreprocessed) feature
                    values, ready to feed into OfflinePreprocessor.preprocess()
    """

    def __init__(
            self,
            pcap_path: str | Path,
            keylog: Optional[str | Path] = None,
            tshark_bin: Optional[str] = None,
    ) -> None:
        self.pcap_path = Path(pcap_path)
        self.keylog = str(keylog) if keylog and Path(keylog).exists() else None
        self.tshark_bin = tshark_bin or find_tshark()

        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP not found: {self.pcap_path}")

        if keylog and not self.keylog:
            print(f"[FileCapture] WARN: keylog not found at {keylog} "
                  "— TLS/HTTP2/QUIC fields will be empty")

    def _build_cmd(self) -> list[str]:
        cmd = [
            self.tshark_bin,
            "-r", str(self.pcap_path),
            "-T", "fields",
            "-E", f"separator={_SEP}",
            "-E", "header=y",
            "-E", "quote=d",
        ]
        if self.keylog:
            cmd += ["-o", f"tls.keylog_file:{self.keylog}"]
        for feat in MODEL_FEATURES:
            cmd += ["-e", feat]
        # ip.src / ipv6.src appended after model features for source IP tracking
        cmd += ["-e", "ip.src", "-e", "ipv6.src"]
        return cmd

    def __iter__(self):
        cmd = self._build_cmd()
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

        try:
            for raw_line in proc.stdout:
                raw_line = raw_line.rstrip("\n")
                if not raw_line:
                    continue

                # first non-empty line is the tshark header
                if not header_cols:
                    clean_header = raw_line.replace('"', "").replace(_SEP, ",")
                    header_cols = [c.strip() for c in clean_header.split(",")]
                    continue

                # extract source IP from raw line before comma→plus substitution
                parts_raw = raw_line.replace('"', "").split(_SEP)
                raw_dict = dict(zip(header_cols, parts_raw))
                source_ip = (raw_dict.get("ip.src") or
                             raw_dict.get("ipv6.src") or None)
                if source_ip:
                    source_ip = source_ip.strip() or None

                # post-process and build single-row DataFrame
                processed_line = postprocess_row(raw_line)
                row = parse_row(header_cols, processed_line)
                df = row_to_dataframe(row)

                yield source_ip, df

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            # log any tshark warnings to stderr
            stderr_out = proc.stderr.read() if proc.stderr else ""
            if stderr_out.strip():
                lines = stderr_out.strip().splitlines()
                print(f"[FileCapture] tshark warnings ({len(lines)} lines, first 3):")
                for line in lines[:3]:
                    print(f"             {line}")


# ═══════════════════════════════════════════════════════════════════════════════
#   load_pcap_as_dataframe  — fast batch extraction for offline use
# ═══════════════════════════════════════════════════════════════════════════════

def load_pcap_as_dataframe(
    pcap_path: str | Path,
    keylog: str | Path | None = None,
    tshark_bin: str | None = None,
) -> tuple[pd.DataFrame, list[str | None]]:
    """
    Run tshark on an entire PCAP in one shot and return a full DataFrame of
    raw (unpreprocessed) features — one row per packet.

    This is the fast path for offline testing: tshark runs once, all output
    is collected with communicate(), then parsed by pd.read_csv in one
    vectorised call.  Much faster than the per-packet FileCapture iterator
    for large PCAPs.

    Parameters
    ----------
    pcap_path  : input PCAP file
    keylog     : TLS SSLKEYLOGFILE (all.txt) for decryption
    tshark_bin : explicit tshark path (auto-detected if None)

    Returns
    -------
    (df, source_ips)
        df         : DataFrame with MODEL_FEATURES columns, raw string values
        source_ips : list of ip.src / ipv6.src per row, aligned to df index
    """
    from io import StringIO

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    tshark = tshark_bin or find_tshark()

    cmd = [
        tshark,
        "-r", str(pcap_path),
        "-T", "fields",
        "-E", f"separator={_SEP}",
        "-E", "header=y",
        "-E", "quote=d",
    ]
    if keylog and Path(keylog).exists():
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    else:
        if keylog:
            print(f"[load_pcap] WARN: keylog not found at {keylog} "
                  "— TLS/HTTP2/QUIC fields will be empty")
    for feat in MODEL_FEATURES:
        cmd += ["-e", feat]
    # ip.src / ipv6.src appended after model features for source IP tracking
    cmd += ["-e", "ip.src", "-e", "ipv6.src"]

    print(f"[load_pcap] Running tshark on {pcap_path.name} ...")
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"tshark exited with code {proc.returncode}:\n{proc.stderr[:300]}"
        )

    if proc.stderr.strip():
        lines = proc.stderr.strip().splitlines()
        print(f"[load_pcap] tshark warnings ({len(lines)} lines, first 3):")
        for line in lines[:3]:
            print(f"            {line}")

    # ── post-process entire output at once ────────────────────────────────────
    # Same three UltraEdit steps applied to the whole string:
    #   1. "," → "+"   (multi-value commas inside fields)
    #   2. strip "     (remove -E quote=d wrapping)
    #   3. "|" → ","   (our separator → standard CSV comma)
    clean = proc.stdout.replace(",", "+").replace('"', "").replace(_SEP, ",")

    csv_lines = clean.strip().splitlines()
    if len(csv_lines) < 2:
        raise RuntimeError("tshark produced no packet rows.")
    print(f"[load_pcap] {len(csv_lines) - 1} packets extracted")

    # ── parse into DataFrame keeping all values as raw strings ───────────────
    df = pd.read_csv(
        StringIO(clean),
        sep=",",
        dtype=str,
        keep_default_na=False,
        na_values=[""],
        on_bad_lines="skip",
    )
    df.columns = [c.strip() for c in df.columns]

    # ── extract source IPs before dropping extra columns ─────────────────────
    source_ips: list[str | None] = []
    for _, row in df.iterrows():
        ip = row.get("ip.src") or row.get("ipv6.src")
        if pd.isna(ip) or str(ip).strip() == "":
            source_ips.append(None)
        else:
            source_ips.append(str(ip).strip())

    # ── keep only model feature columns ──────────────────────────────────────
    df = df.reindex(columns=MODEL_FEATURES)
    df = df.replace("", float("nan"))

    return df, source_ips


# ═══════════════════════════════════════════════════════════════════════════════
#   LiveCapture
# ═══════════════════════════════════════════════════════════════════════════════

class LiveCapture:
    """
    Captures live packets from a network interface using tshark, extracts
    the 46 model features, preprocesses each row, and puts it on a queue.

    Parameters
    ----------
    interface    : network interface name (e.g. "eth0", "en0")
    preprocessor : fitted LivePreprocessor instance
    bpf_filter   : optional BPF capture filter string (e.g. "tcp port 443")
    keylog_file  : path to NSS SSLKEYLOGFILE for live TLS decryption.
                   Defaults to /tmp/sslkeys.log — set SSLKEYLOGFILE in the
                   environment of the monitored application so it writes
                   TLS session keys there.
    tshark_bin   : explicit tshark binary path (auto-detected if None)

    Queue items
    -----------
    Each item placed on self.queue is:
        (source_ip: str | None, preprocessed_df: pd.DataFrame)

    source_ip     : raw IP string from ip.src or ipv6.src, for firewall use
    preprocessed_df : single-row DataFrame ready for model.predict()
    """

    def __init__(
            self,
            interface: str,
            preprocessor: LivePreprocessor,
            bpf_filter: Optional[str] = None,
            keylog_file: Optional[str] = None,
            tshark_bin: Optional[str] = None,
    ) -> None:
        if interface is None:
            interface = "eth0" if platform.system() in ("Windows", "Linux") else "en0"

        self.interface = interface
        self.preprocessor = preprocessor
        self.bpf_filter = bpf_filter
        self.tshark_bin = tshark_bin or find_tshark()
        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

        # Resolve and ensure keylog file exists
        self.keylog_file = keylog_file or _DEFAULT_KEYLOG
        if not os.path.exists(self.keylog_file):
            open(self.keylog_file, "a").close()
        # Signal the monitored application to write TLS keys here
        os.environ["SSLKEYLOGFILE"] = self.keylog_file

    # ── internal ──────────────────────────────────────────────────────────────

    def _build_cmd(self) -> list[str]:
        """
        Build the tshark live-capture command.
        -l enables line-buffered output so rows arrive immediately.
        ip.src and ipv6.src are appended AFTER model features — they are used
        for source IP identification but are NOT model features.
        """
        cmd = [
            self.tshark_bin,
            "-i", self.interface,
            "-l",  # line-buffered — critical for streaming
            "-T", "fields",
            "-E", f"separator={_SEP}",
            "-E", "header=y",
            "-E", "quote=d",
        ]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        cmd += ["-o", f"tls.keylog_file:{self.keylog_file}"]
        for feat in MODEL_FEATURES:
            cmd += ["-e", feat]
        # Append source IP fields for firewall use (after model features)
        cmd += ["-e", "ip.src", "-e", "ipv6.src"]
        return cmd

    def _capture_loop(self) -> None:
        cmd = self._build_cmd()
        print(f"[LiveCapture] interface={self.interface}"
              + (f"  filter='{self.bpf_filter}'" if self.bpf_filter else ""))
        print(f"[LiveCapture] TLS keylog: {self.keylog_file}")
        print(f"[LiveCapture] tshark: {self.tshark_bin}")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,  # line-buffered
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

                # ── first non-empty line is the header ────────────────────
                if not header_cols:
                    # Strip quotes and swap separator — no comma→plus here
                    # since header contains column names, not numeric values
                    clean_header = raw_line.replace('"', "").replace(_SEP, ",")
                    header_cols = [c.strip() for c in clean_header.split(",")]
                    print(f"[LiveCapture] tshark started: {len(header_cols)} columns")
                    continue

                # ── extract source IP before comma→plus substitution ──────
                parts_raw = raw_line.replace('"', "").split(_SEP)
                raw_dict = dict(zip(header_cols, parts_raw))
                source_ip = (raw_dict.get("ip.src") or
                             raw_dict.get("ipv6.src") or None)
                if source_ip:
                    source_ip = source_ip.strip() or None

                # ── post-process and parse ────────────────────────────────
                processed_line = postprocess_row(raw_line)
                row = parse_row(header_cols, processed_line)
                df = row_to_dataframe(row)

                # ── preprocess and enqueue ────────────────────────────────
                try:
                    preprocessed = self.preprocessor.preprocess(df)
                    self.queue.put((source_ip, preprocessed))
                    seen += 1
                except Exception as exc:
                    errors += 1
                    if errors <= 10:
                        print(f"[LiveCapture] preprocess error (pkt {seen + errors}): {exc}")

        except Exception as exc:
            print(f"[LiveCapture] fatal loop error: {exc}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            print(f"[LiveCapture] stopped — queued={seen}, errors={errors}")

    # ── public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the capture in a background daemon thread."""
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        print(f"[LiveCapture] capture thread started on [{self.interface}]")

    def stop(self) -> None:
        """Signal the capture loop to stop gracefully."""
        self.stop_event.set()
        print("[LiveCapture] stop requested.")