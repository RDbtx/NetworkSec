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
from src.model.preprocessing.scaling import FLAG_COLS, TO_SCALE_COLUMNS
from src.firewall.data_extraction import LiveCapture
from collections import defaultdict, deque

SRC_PATH = pathlib.Path(__file__).parent.parent
MODEL_PATH = os.path.join(SRC_PATH, "./firewall/model/Blackwall.joblib")
SCALER_PATH = os.path.join(SRC_PATH, "./model/output/scaler.joblib")

# Classes that trigger a block action
TO_BLOCK_IMMEDIATELY = {"HTTP/2-attacks"}
TO_BLOCK_AFTER_N_INSTANCES = {"DDoS-flooding", "DDoS-loris"}
DDOS_STRIKES_TO_BLOCK = 100
DDOS_WINDOW_SECONDS = 60


# ===========================================
# ---       Input Data Preprocessor       ---
# ===========================================


class LivePreprocessor:
    def __init__(self, saved_scaler=None):
        if saved_scaler is not None:
            self.scaler = saved_scaler["scaler"] if isinstance(saved_scaler, dict) else saved_scaler
            self.scaler_columns = (saved_scaler["scaler_columns"]
                                   if isinstance(saved_scaler, dict) else TO_SCALE_COLUMNS)
            # ohe_columns is saved into scaler.joblib by scaling.py's minmax_scale()
            # — no need to load the training CSV on the deployment machine
            self.ohe_columns = (saved_scaler["ohe_columns"]
                                if isinstance(saved_scaler, dict) and "ohe_columns" in saved_scaler
                                else [])
            if not self.ohe_columns:
                raise RuntimeError(
                    "[Preprocessor] scaler.joblib does not contain 'ohe_columns'. "
                    "Re-run scaling.py to regenerate the scaler with OHE column info included."
                )
            print(f"[Preprocessor] Loaded training scaler "
                  f"({len(self.scaler_columns)} scale cols, "
                  f"{len(self.ohe_columns)} OHE cols).")
        else:
            raise RuntimeError(
                "[Preprocessor] No saved scaler found. "
                "Run scaling.py to generate scaler.joblib before starting the firewall."
            )

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
        # use scaler_columns (exact order from training) not TO_SCALE_COLUMNS
        # to ensure feature alignment matches what the scaler was fit on
        present_scale_cols = [c for c in self.scaler_columns if c in df.columns]
        df[present_scale_cols] = df[present_scale_cols].astype(float)
        df[present_scale_cols] = self.scaler.transform(df[present_scale_cols])
        return df

    def preprocess(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df = self.fill_missing(df)
        df = self.resolve_compound(df)
        df = self.ohe(df)
        df = self.scale(df)
        return df


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
            batch_size: int = 8,
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

        # load saved training scaler if available — ensures feature scaling
        # matches training distribution exactly instead of fitting on warmup
        saved_scaler = None
        if os.path.exists(SCALER_PATH):
            try:
                # pass the full dict so LivePreprocessor gets both scaler + column list
                saved_scaler = joblib.load(SCALER_PATH)
                print(f"[Firewall] Loaded training scaler from {SCALER_PATH}")
            except Exception as e:
                print(f"[Firewall] Could not load scaler: {e} — will use warmup instead")

        self.preprocessor = LivePreprocessor(saved_scaler=saved_scaler)

        machine_ip = get_interface_ip(interface)
        if machine_ip:
            bpf = f"dst host {machine_ip} or dst host 127.0.0.1 or dst host ::1"
            if bpf_filter:
                bpf = f"({bpf_filter}) and ({bpf})"
        else:
            bpf = bpf_filter

        self.capture = LiveCapture(
            interface=interface,
            bpf_filter=bpf_filter,
            keylog_file=keylog_file,
        )

        # Stats
        self.stats = {name: 0 for name in self.label_names}
        self.stats["total"] = 0
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

    def run(self):
        """Start capturing and classifying. Blocks until KeyboardInterrupt."""
        self.capture.start()
        print("[Firewall] Classification started — training scaler loaded, no warmup needed.")

        try:
            while not self.capture.stop_event.is_set():

                # Block briefly waiting for at least one packet
                try:
                    source_ip, raw_df = self.capture.queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                # Collect first packet then drain up to batch_size - 1 more
                # without blocking — process whatever is immediately available
                batch_ips = [source_ip]
                batch_dfs = [raw_df]

                for _ in range(self.batch_size - 1):
                    try:
                        source_ip, raw_df = self.capture.queue.get_nowait()
                        batch_ips.append(source_ip)
                        batch_dfs.append(raw_df)
                    except queue.Empty:
                        break

                # Run inference on the batch
                combined = pd.concat(batch_dfs, ignore_index=True)
                labels = self.predict(combined)
                for i, label in enumerate(labels):
                    self.stats["total"] += 1
                    self.handle_prediction(label, batch_ips[i])

        except KeyboardInterrupt:
            print("\n[Firewall] Shutting down...")
            self.capture.stop()
