import pyshark
import pandas as pd
import queue
import threading
import platform
import os
from typing import Optional
from src.model.preprocessing.filtering import FEATURES
import subprocess


# Mapping: feature name → pyshark layer.field path
FIELD_MAP = {
    "frame.len": ("frame_info", "len"),  # pyshark exposes frame as packet.frame_info
    "ip.len": ("ip", "len"),
    "tcp.len": ("tcp", "len"),
    "tcp.hdr_len": ("tcp", "hdr_len"),
    "tcp.flags.ack": ("tcp", "flags_ack"),
    "tcp.flags.push": ("tcp", "flags_push"),
    "tcp.flags.reset": ("tcp", "flags_reset"),
    "tcp.flags.syn": ("tcp", "flags_syn"),
    "tcp.flags.fin": ("tcp", "flags_fin"),
    "tcp.window_size_value": ("tcp", "window_size_value"),
    "tcp.option_len": ("tcp", "option_len"),
    "udp.length": ("udp", "length"),
    "tls.record.length": ("tls", "record_length"),
    "tls.reassembled.length": ("tls", "reassembled_length"),
    "tls.handshake.length": ("tls", "handshake_length"),
    "tls.handshake.certificates_length": ("tls", "handshake_certificates_length"),
    "tls.handshake.certificate_length": ("tls", "handshake_certificate_length"),
    "tls.handshake.session_id_length": ("tls", "handshake_session_id_length"),
    "tls.handshake.cipher_suites_length": ("tls", "handshake_cipher_suites_length"),
    "tls.handshake.extensions_length": ("tls", "handshake_extensions_length"),
    "tls.handshake.client_cert_vrfy.sig_len": ("tls", "handshake_client_cert_vrfy_sig_len"),
    "quic.packet_length": ("quic", "packet_length"),
    "quic.long.packet_type": ("quic", "long_packet_type"),
    "quic.packet_number_length": ("quic", "packet_number_length"),
    "quic.length": ("quic", "length"),
    "quic.nci.connection_id.length": ("quic", "nci_connection_id_length"),
    "quic.crypto.length": ("quic", "crypto_length"),
    "quic.fixed_bit": ("quic", "fixed_bit"),
    "quic.spin_bit": ("quic", "spin_bit"),
    "quic.stream.fin": ("quic", "stream_fin"),
    "quic.stream.len": ("quic", "stream_len"),
    "quic.token_length": ("quic", "token_length"),
    "quic.padding_length": ("quic", "padding_length"),
    "http2.length": ("http2", "length"),
    "http2.header.length": ("http2", "header_length"),
    "http2.header.name.length": ("http2", "header_name_length"),
    "http2.header.value.length": ("http2", "header_value_length"),
    "http2.headers.content_length": ("http2", "headers_content_length"),
    "http3.frame_length": ("http3", "frame_length"),
    "http3.settings.qpack.max_table_capacity": ("http3", "settings_qpack_max_table_capacity"),
    "http3.settings.max_field_section_size": ("http3", "settings_max_field_section_size"),
    "dns.flags.response": ("dns", "flags_response"),
    "dns.count.queries": ("dns", "count_queries"),
    "dns.count.answers": ("dns", "count_answers"),
    "http.content_length": ("http", "content_length"),
    "http.content_type": ("http", "content_type"),
}

KEYLOG_PATH = "/tmp/sslkeys.log"
if not os.path.exists(KEYLOG_PATH):
    open(KEYLOG_PATH, "a").close()
os.environ["SSLKEYLOGFILE"] = KEYLOG_PATH


def get_value(packet, layer_name: str, field_name: str):
    """Return the field value from a pyshark packet, or None if absent."""
    try:
        layer = getattr(packet, layer_name)
        return getattr(layer, field_name)
    except AttributeError:
        return None


def get_http2_value(packet, field_name: str):
    """
    HTTP/2 fields in pyshark are nested inside http2.stream in _all_fields.
    Some fields (e.g. http2.header.length) are nested further inside lists/dicts.
    This helper searches the stream dict and one level of sub-dicts/lists.
    field_name should be dot-notation e.g. 'http2.length', 'http2.header.length'
    """
    try:
        layer = packet.http2
        # attempt flat pyshark attribute first
        attr = field_name.replace(".", "_")
        val = getattr(layer, attr, None)
        if val is not None:
            return val
        # dig into http2.stream dict
        stream = layer._all_fields.get("http2.stream", {})
        val = stream.get(field_name)
        if val is not None:
            return val
        # search one level deeper — some fields are inside nested dicts/lists
        # e.g. http2.header.length is inside the http2.header list items
        for v in stream.values():
            if isinstance(v, dict):
                val = v.get(field_name)
                if val is not None:
                    return val
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        val = item.get(field_name)
                        if val is not None:
                            return val
        return None
    except AttributeError:
        return None


def _search_dict_recursive(d: dict, key: str, max_depth: int = 5):
    """Recursively search a nested dict/list structure for a key, up to max_depth."""
    if max_depth == 0:
        return None
    if isinstance(d, dict):
        if key in d:
            return d[key]
        for v in d.values():
            result = _search_dict_recursive(v, key, max_depth - 1)
            if result is not None:
                return result
    elif isinstance(d, list):
        for item in d:
            result = _search_dict_recursive(item, key, max_depth - 1)
            if result is not None:
                return result
    return None


def get_tls_value(packet, field_name: str):
    """
    TLS fields in pyshark are nested inside tls.record (dict or list of dicts)
    which itself contains tls.handshake and further nested structures.
    Uses recursive search to find the field at any nesting level.
    field_name is the pyshark attribute name e.g. 'record_length' which maps
    to the dot-notation key 'tls.record.length' in _all_fields.
    """
    try:
        layer = packet.tls
        # try flat pyshark attribute first
        val = getattr(layer, field_name, None)
        if val is not None:
            return val
        # build dot-notation key from the FEATURES column name
        # e.g. field_name='record_length' but actual key is 'tls.record.length'
        # We pass the original feature key from FIELD_MAP so use that directly
        all_f = layer._all_fields
        result = _search_dict_recursive(all_f, field_name)
        return result
    except AttributeError:
        return None


def extract_features(packet) -> dict:
    """
    Extract all model features from a single pyshark packet.
    HTTP/2 fields require special nested access via get_http2_value.
    Missing fields are returned as None (handled downstream by the scaler pipeline).
    """
    row = {}
    for feature, (layer, field) in FIELD_MAP.items():
        if layer == "http2":
            # feature IS the full dot-notation key e.g. "http2.header.length"
            row[feature] = get_http2_value(packet, feature)
        elif layer == "tls":
            # pass the full feature name (dot-notation) as the search key
            # e.g. feature="tls.record.length" matches exactly what is in _all_fields
            row[feature] = get_tls_value(packet, feature)
        else:
            row[feature] = get_value(packet, layer, field)
    return row


def packet_to_dataframe(packet):
    """Convert one packet into a single-row DataFrame ready for the firewall."""
    if hasattr(packet, "ip") and hasattr(packet.ip, "src"):
        source_ip = str(packet.ip.src)
    elif hasattr(packet, "ipv6") and hasattr(packet.ipv6, "src"):
        source_ip = str(packet.ipv6.src)
    else:
        source_ip = None
    row = extract_features(packet)

    # DEBUG TLS raw fields
    if hasattr(packet, 'tls'):
        with open('/tmp/tls_debug.log', 'a') as f:
            f.write(f"[TLS ALL_FIELDS] {packet.tls._all_fields}\n")

    # DEBUG — write to file to bypass GUI print interception
    # remove this block once features are confirmed working
    with open("/tmp/http2_debug.log", "a") as f:
        layers = [layer.layer_name for layer in packet.layers]
        tls_feats = {k: v for k, v in row.items() if k.startswith("tls") and v is not None}
        http2_feats = {k: v for k, v in row.items() if k.startswith("http2") and v is not None}
        tcp_feats = {k: v for k, v in row.items() if k.startswith("tcp") and v is not None and v != 0 and v != "0"}
        f.write(f"[PKT] layers={layers}\n")
        f.write(f"  tcp={tcp_feats}\n")
        f.write(f"  tls={tls_feats}\n")
        f.write(f"  http2={http2_feats}\n")

    return source_ip, pd.DataFrame([row], columns=FEATURES)


# ---------------------------------------------------------------------------
#                           Packets Capture
# ---------------------------------------------------------------------------

class LiveCapture:
    """
    Captures live packets on *interface*, optionally decrypting TLS via a
    SSLKEYLOGFILE so that HTTP/2 and HTTP/3 (QUIC) frames are visible to
    Wireshark / tshark and therefore to pyshark.

    Parameters
    ----------
    interface   : network interface name (e.g. "en0", "eth0")
    bpf_filter  : optional BPF capture filter string
    keylog_file : path to an NSS key-log file used for TLS decryption.
                  • Pass an explicit path to use a pre-existing file.
                  • Pass None (default) to auto-detect the platform default
                    path AND set the SSLKEYLOGFILE env-var so the current
                    process (and any child browsers) will write keys there.
    """

    def __init__(
            self,
            interface: str,
            bpf_filter: Optional[str] = None,
            keylog_file: Optional[str] = None,
    ):
        if interface is None:
            interface = "eth0" if platform.system() in ("Windows", "Linux") else "en0"

        self.interface = interface
        self.bpf_filter = bpf_filter
        self.keylog_file = keylog_file  # resolved in capture_loop
        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def resolve_keylog_path(self) -> str:
        if self.keylog_file:
            path = self.keylog_file
        else:
            path = KEYLOG_PATH  # use the module-level constant already set at import time

        if not os.path.exists(path):
            with open(path, "a"):
                pass

        return path

    # ------------------------------------------------------------------
    # Capture loop (runs in background thread)
    # ------------------------------------------------------------------

    def capture_loop(self):
        kwargs = dict(
            interface=self.interface,
            use_json=True,
            include_raw=False,
        )

        if self.bpf_filter:
            kwargs["bpf_filter"] = self.bpf_filter

        # ── TLS key-log setup ──────────────────────────────────────────
        keylog = self.resolve_keylog_path()

        # custom_parameters passes -o/-d flags directly to tshark.
        # override_prefs is unreliable for live captures in many pyshark versions.
        #
        # -o tls.keylog_file       → decrypt TLS using the SSLKEYLOGFILE
        # -d tcp.port==8443,tls    → treat TCP 8443 as TLS (not just port 443)
        # -d udp.port==4433,quic   → treat UDP 4433 as QUIC (HTTP/3)
        # -Y http2 or quic         → display filter: only pass fully dissected
        #                            HTTP/2 or QUIC packets to Python, skipping
        #                            raw TCP/TLS handshake frames that would just
        #                            waste warmup budget with all-zero features
        # ── Preset 1 — FULL MONITORING (default, no port restriction) ─────
        # Captures all inbound traffic. The -d hints still ensure HTTP/2 and
        # QUIC are dissected correctly on non-standard ports when they appear.
        kwargs["custom_parameters"] = [
            "-o", f"tls.keylog_file:{keylog}",
            "-d", "tcp.port==8443,tls",
            "-d", "udp.port==4433,quic",
            "-d", "tcp.port==8080,http",  # plain HTTP/1.1 server
        ]

        # ── Preset 2 — HTTP/2 LOCAL TEST (uncomment to activate) ──────────
        # Filters to only fully-decoded HTTP/2 packets destined for the local
        # server. Use this when testing h2load / slowhttptest attacks so home
        # wifi noise doesn't pollute the warmup or classification.
        # Comment out Preset 1 above and uncomment below to switch.
        #
        # kwargs["custom_parameters"] = [
        #     "-o", f"tls.keylog_file:{keylog}",
        #     "-d", "tcp.port==8443,tls",
        #     "-d", "udp.port==4433,quic",
        #     "-Y", "http2 and ip.dst == 127.0.0.1",
        # ]

        # ── Preset 3 — QUIC/HTTP3 LOCAL TEST (uncomment to activate) ──────
        # Same as Preset 2 but for QUIC/HTTP3 flood testing on UDP 4433.
        # Comment out the active preset above and uncomment below to switch.
        #
        # kwargs["custom_parameters"] = [
        #     "-o", f"tls.keylog_file:{keylog}",
        #     "-d", "tcp.port==8443,tls",
        #     "-d", "udp.port==4433,quic",
        #     "-Y", "quic and ip.dst == 127.0.0.1",
        # ]
        kwargs["tshark_path"] = subprocess.run(
            ["which", "tshark"], capture_output=True, text=True
        ).stdout.strip()  # auto-detect tshark path instead of hardcoding /usr/bin/tshark

        print(f"[LiveCapture] TLS key-log: {keylog}")
        capture = pyshark.LiveCapture(**kwargs)
        try:
            for packet in capture.sniff_continuously():
                if self.stop_event.is_set():
                    break
                try:
                    source_ip, df = packet_to_dataframe(packet)
                    self.queue.put((source_ip, df))
                except Exception as e:
                    print(f"[capture] Skipping packet due to error: {e}")
        finally:
            capture.close()

    def start(self):
        self.thread = threading.Thread(target=self.capture_loop, daemon=True)
        self.thread.start()
        print(
            f"[LiveCapture] Live capture started on interface [{self.interface}]"
            + (f" with filter '{self.bpf_filter}'" if self.bpf_filter else "")
        )

    def stop(self):
        self.stop_event.set()
        print("[LiveCapture] has stopped.")
