import os
import time
import queue
import joblib
import socket
import pandas as pd
import pathlib
import psutil
import subprocess
import platform
from sklearn.preprocessing import MinMaxScaler
from src.model.preprocessing.scaling import FLAG_COLS, TO_SCALE_COLUMNS
from src.firewall.data_extraction import LiveCapture
from collections import defaultdict, deque

SRC_PATH = pathlib.Path(__file__).parent.parent
MODEL_PATH = os.path.join(SRC_PATH, "./firewall/model/Blackwall.joblib")
DATASET_PATH = os.path.join(SRC_PATH, "./model/output/pcap-all-final.csv")

# Classes that trigger a block action
TO_BLOCK_IMMEDIATELY = {"HTTP/2-attacks"}
TO_BLOCK_AFTER_N_INSTANCES = {"DDoS-flooding", "DDoS-loris", "Transport-layer"}
DDOS_STRIKES_TO_BLOCK = 100
DDOS_WINDOW_SECONDS = 60


# ===========================================
# ---       Input Data Preprocessor       ---
# ===========================================


class LivePreprocessor:
    def __init__(self, warmup_packets: int = 500):
        self.warmup_packets = warmup_packets
        self.scaler = MinMaxScaler()
        self.scaler_fitted = False
        self.ohe_columns: list = []
        self._warmup_buffer: list = []

        # checks which columns to oh encode
        df = pd.read_csv(DATASET_PATH, nrows=0)
        self.ohe_columns = [c for c in df.columns if c != "Label"]

    # ===========================================
    # ---   Preprocessing Helper Functions    ---
    # ===========================================

    def fill_missing(self, df: pd.DataFrame) -> pd.DataFrame:
        for col in FLAG_COLS:
            if col in df.columns:
                df[col] = df[col].fillna(-1)
        df = df.fillna(0)
        return df

    def resolve_compound(self, df: pd.DataFrame) -> pd.DataFrame:
        obj_cols = [c for c in df.select_dtypes(include=["object", "str"]).columns]
        for col in obj_cols:
            def safe_eval(v):
                if not isinstance(v, str):
                    return v
                if not any(op in v for op in ('+', '-', '*', '/')):
                    return v
                try:
                    return pd.eval(str(v))
                except Exception:
                    return v

            df[col] = df[col].apply(safe_eval)
        return df

    def ohe(self, df: pd.DataFrame) -> pd.DataFrame:
        present_flag_cols = [c for c in FLAG_COLS if c in df.columns]

        for col in present_flag_cols:
            df[col] = df[col].astype(str)

        df = pd.get_dummies(df, columns=present_flag_cols)
        df = df.reindex(columns=self.ohe_columns, fill_value=0)

        return df

    def scale(self, df: pd.DataFrame) -> pd.DataFrame:
        present_scale_cols = [c for c in TO_SCALE_COLUMNS if c in df.columns]
        df[present_scale_cols] = df[present_scale_cols].astype(float)
        df[present_scale_cols] = self.scaler.transform(df[present_scale_cols])
        return df

    def fit_scaler(self, batch: pd.DataFrame):
        present_scale_cols = [c for c in TO_SCALE_COLUMNS if c in batch.columns]
        batch[present_scale_cols] = batch[present_scale_cols].astype(float)
        self.scaler.fit(batch[present_scale_cols])
        self.scaler_fitted = True

    def preprocess(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df = self.fill_missing(df)
        df = self.resolve_compound(df)
        df = self.ohe(df)
        if self.scaler_fitted:
            df = self.scale(df)
        return df

    def add_to_warmup(self, df: pd.DataFrame) -> bool:
        """
        Buffer a packet for warmup. Returns True once the scaler has been fitted.
        """
        if self.scaler_fitted:
            return True
        partial = df.copy()
        partial = self.fill_missing(partial)
        partial = self.resolve_compound(partial)
        partial = self.ohe(partial)
        self._warmup_buffer.append(partial)

        if len(self._warmup_buffer) >= self.warmup_packets:
            batch = pd.concat(self._warmup_buffer, ignore_index=True).fillna(0)
            self.fit_scaler(batch)
            self._warmup_buffer.clear()
            return True
        return False


def get_interface_ip(interface_name: str) -> str | None:
    """Return the IPv4 address of the given network interface, or None."""
    addresses = psutil.net_if_addrs()
    if interface_name in addresses:
        for addr in addresses[interface_name]:
            if addr.family == socket.AF_INET:
                return addr.address
    return None


# ===========================================
# ---             Firewall                ---
# ===========================================

class Firewall:
    def __init__(
            self,
            model_path: str = MODEL_PATH,
            interface: str = "eth0",
            bpf_filter: str = None,
            block: bool = False,
            warmup_packets: int = 500,
            batch_size: int = 1,
            keylog_file: str = None,
    ):

        self.block = block
        self.batch_size = batch_size
        self.blocked_ips: set = set()

        # Load model + encoder
        model = os.path.basename(model_path.removesuffix(".joblib"))
        print(f"[Firewall] Loading model...")
        checkpoint = joblib.load(model_path)
        print(f"[Firewall] Loaded model [{model}]!")
        self.model = checkpoint["model"]
        self.encoder = checkpoint["encoder"]
        self.label_names: list = list(self.encoder.classes_)

        self.preprocessor = LivePreprocessor(warmup_packets=warmup_packets)

        machine_ip = get_interface_ip(interface)
        if machine_ip:
            bpf = f"dst host {machine_ip} || dst host 127.0.0.1"
            if bpf_filter:
                bpf = f"({bpf_filter}) and ({bpf})"
        else:
            bpf = bpf_filter
        self.capture = LiveCapture(interface=interface, bpf_filter=bpf)

        # Stats
        self.stats = {name: 0 for name in self.label_names}
        self.stats["total"] = 0
        self.stats["warmup"] = 0
        self.start_time = time.time()

        # blocked ips
        self.ddos_strikes = defaultdict(deque)  # ip -> deque[timestamps]

    # ===========================================
    # ---       Firewall Helper Functions     ---
    # ===========================================

    def predict(self, df: pd.DataFrame) -> list:
        """Preprocess and run model inference. Returns list of label strings."""
        try:
            processed = self.preprocessor.preprocess(df)
            # Align feature order to what the model expects
            X = processed.values.astype(float)
            indices = self.model.predict(X)
            return [self.label_names[i] for i in indices]
        except Exception as e:
            print(f"[Firewall] Prediction error: {e}")
            return ["Unknown"] * len(df)

    def should_block_ip(self, ip: str, label: str) -> bool:
        # Already blocked
        if ip in self.blocked_ips:
            return False

        # Immediate block class
        if label in TO_BLOCK_IMMEDIATELY:
            return True

        # Strike-based logic
        if label in TO_BLOCK_AFTER_N_INSTANCES:
            now = time.time()
            dq = self.ddos_strikes[ip]
            dq.append(now)

            # Remove timestamps older than window
            cutoff = now - DDOS_WINDOW_SECONDS
            while dq and dq[0] < cutoff:
                dq.popleft()

            return len(dq) >= DDOS_STRIKES_TO_BLOCK

        return False

    def handle_prediction(self, label: str, source_ip: str):
        self.stats[label] = self.stats.get(label, 0) + 1

        if label in TO_BLOCK_IMMEDIATELY or label in TO_BLOCK_AFTER_N_INSTANCES:
            print(f"[WARNING] ⚠  Attack detected: {label:<25} |\tsrc== {source_ip or 'unknown'}")
            if self.should_block_ip(source_ip, label):
                success = self.block_ip(source_ip)
                if success:
                    if source_ip:
                        self.ddos_strikes[source_ip].clear()
                else:
                    print(f"[Firewall] BLOCK FAILED for {source_ip} — check sudo permissions")

        else:
            print(f"[ALLOW] ✓  Normal traffic from {source_ip or 'unknown':<25} | label={label}")

    def block_ip(self, ip: str) -> bool:
        if not self.block:
            # Simulation mode: track without actually blocking
            self.blocked_ips.add(ip)
            print(f"[Firewall] [SIM] Would block {ip} (block=False, simulation only)")
            return True

        system = platform.system()
        try:
            if system == "Darwin":  # macOS — use pfctl
                subprocess.run(
                    ["sudo", "pfctl", "-t", "blackwall_blocked", "-T", "add", ip],
                    check=True, capture_output=True
                )
            elif system == "Linux":
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True
                )
            elif system == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=Blackwall_Block_{ip}", "dir=in", "action=block",
                     f"remoteip={ip}"],
                    check=True, capture_output=True
                )
            # Only add to tracked set if the OS command actually succeeded
            self.blocked_ips.add(ip)
            print(f"[Firewall] Blocked {ip} ({system})")
            return True
        except subprocess.CalledProcessError as e:
            # Do NOT add to blocked_ips — the OS rule failed, IP is not actually blocked
            print(f"[Firewall] Failed to block {ip} (sudo/permissions error?): {e.stderr.decode() if e.stderr else e}")
            return False

    def unblock_ip(self, ip: str) -> bool:  # Added return type hint
        if not self.block:
            self.blocked_ips.discard(ip)
            print(f"[Firewall] [SIM] Removed {ip} from simulation block list")
            return True  # Success in simulation

        system = platform.system()
        try:
            if system == "Darwin":
                subprocess.run(
                    ["sudo", "pfctl", "-t", "blackwall_blocked", "-T", "delete", ip],
                    check=True, capture_output=True
                )
            elif system == "Linux":
                # Note: Linux often needs 'sudo' as well unless running as root
                subprocess.run(
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True
                )
            elif system == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name=Blackwall_Block_{ip}"],
                    check=True, capture_output=True
                )

            # Only discard from internal set if the OS command succeeded
            self.blocked_ips.discard(ip)
            print(f"[Firewall] Unblocked {ip}!")
            return True  # Success!

        except subprocess.CalledProcessError as e:
            print(f"[Firewall] Failed to unblock {ip}: {e.stderr.decode() if e.stderr else e}")
            return False  # Failure!

    def print_stats(self):
        elapsed = time.time() - self.start_time
        total = self.stats["total"]
        pps = total / elapsed if elapsed > 0 else 0
        print(f"\n--- Stats ({elapsed:.0f}s | {total} pkts | {pps:.1f} pkt/s) ---")
        for name in self.label_names:
            count = self.stats.get(name, 0)
            pct = 100 * count / total if total else 0
            print(f"  {name:<22} {count:>6}  ({pct:.1f}%)")
        print("\n--- Currently blocked ips ---")
        if self.blocked_ips is not None and len(self.blocked_ips) > 0:
            for ip in self.blocked_ips:
                print(f" {ip}")
        else:
            print(" None")
        print()

    # ===========================================
    # ---        Main Firewall Pipeline       ---
    # ===========================================

    # Maximum packets to hold in queue — drop oldest if exceeded to stay real-time
    QUEUE_MAX_SIZE = 500

    def run(self):
        """Start capturing and classifying. Blocks until KeyboardInterrupt."""
        self.capture.start()
        print(f"[Preprocessor] Warming up preprocessor on first {self.preprocessor.warmup_packets} packets...")

        last_stats = time.time()

        try:
            while not self.capture.stop_event.is_set():

                # ── Drain up to batch_size packets at once ─────────────────
                batch_ips: list = []
                batch_dfs: list = []

                # Block briefly waiting for at least one packet
                try:
                    source_ip, raw_df = self.capture.queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                # Drop stale packets if queue is too deep (stay real-time)
                q_size = self.capture.queue.qsize()
                if q_size > self.QUEUE_MAX_SIZE:
                    dropped = q_size - self.QUEUE_MAX_SIZE
                    for _ in range(dropped):
                        try:
                            self.capture.queue.get_nowait()
                        except queue.Empty:
                            break
                    print(f"[Firewall] Dropped {dropped} stale packets to stay real-time")

                # Collect first packet
                packets = [(source_ip, raw_df)]

                # Drain remaining available packets up to batch_size
                for _ in range(self.batch_size - 1):
                    try:
                        packets.append(self.capture.queue.get_nowait())
                    except queue.Empty:
                        break

                # ── Process each packet ────────────────────────────────────
                for source_ip, raw_df in packets:
                    self.stats["total"] += 1

                    # Warmup phase
                    if not self.preprocessor.scaler_fitted:
                        ready = self.preprocessor.add_to_warmup(raw_df)
                        self.stats["warmup"] += 1
                        if ready:
                            print("[Preprocessor] Warmup complete. Classification started!\n")
                        continue

                    batch_ips.append(source_ip)
                    batch_dfs.append(raw_df)

                # ── Run inference on the collected batch ───────────────────
                if batch_dfs:
                    combined = pd.concat(batch_dfs, ignore_index=True)
                    labels = self.predict(combined)
                    for i, label in enumerate(labels):
                        self.handle_prediction(label, batch_ips[i])

        except KeyboardInterrupt:
            print("\n[Firewall] Shutting down...")
            self.capture.stop()
