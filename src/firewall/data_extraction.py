import pyshark
import pandas as pd
import queue
import threading
import platform
from typing import Optional
from src.model.preprocessing.filtering import FEATURES

# Mapping: feature name → pyshark layer.field path
FIELD_MAP = {
    "frame.len": ("frame", "len"),
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

def get_value(packet, layer_name: str, field_name: str):
    """Return the field value from a pyshark packet, or None if absent."""
    try:
        layer = getattr(packet, layer_name)
        return getattr(layer, field_name)
    except AttributeError:
        return None


def extract_features(packet) -> dict:
    """
    Extract all model features from a single pyshark packet.
    Missing fields are returned as None (will be handled by the scaler pipeline).
    """
    row = {}
    for feature, (layer, field) in FIELD_MAP.items():
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
    return source_ip, pd.DataFrame([row], columns=FEATURES)

# ---------------------------------------------------------------------------
#                       Packets Capture
# ---------------------------------------------------------------------------

class LiveCapture:

    def __init__(self, interface: str, bpf_filter: Optional[str] = None):
        if interface is None:
            sysname = platform.system()
            if sysname in ("Windows", "Linux"):
                interface = "eth0"
            else:
                interface = "en0"

        self.interface = interface
        self.bpf_filter = bpf_filter
        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def capture_loop(self):
        kwargs = dict(
            interface=self.interface,
            use_json=True,
            include_raw=False,
        )
        if self.bpf_filter:
            kwargs["bpf_filter"] = self.bpf_filter

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
        print(f"[LiveCapture] Live capture started on interface [{self.interface}]!"
              + (f" with filter '{self.bpf_filter}'" if self.bpf_filter else ""))

    def stop(self):
        self.stop_event.set()
        print("[LiveCapture] has stopped.")
