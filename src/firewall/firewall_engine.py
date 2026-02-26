import os
import time
import joblib
import pandas as pd
import pathlib
from sklearn.preprocessing import MinMaxScaler
from src.model.preprocessing.scaling import FLAG_COLS, TO_SCALE_COLUMNS
from src.firewall.data_extraction import LiveCapture

SRC_PATH = pathlib.Path(__file__).parent.parent
MODEL_PATH = os.path.join(SRC_PATH, "./model/output/saved_models/XGBOOST_classifier.joblib")
DATASET_PATH = os.path.join(SRC_PATH, "./model/output/pcap-all-final.csv")

# Classes that trigger a block action
ATTACK_CLASSES = {"DDoS-flooding", "DDoS-loris", "HTTP/2-attacks"}


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
        print(f"[Preprocessor] Loaded {len(self.ohe_columns)} model columns")

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
            df[col] = df[col].apply(
                lambda v: pd.eval(str(v)) if isinstance(v, str) and any(op in v for op in ('+', '-', '*', '/')) else v
            )
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
    ):

        self.block = block
        self.batch_size = batch_size
        self.blocked_ips: set = set()

        # Load model + encoder
        print(f"[Firewall] Loading model from {model_path} ...")
        checkpoint = joblib.load(model_path)
        self.model = checkpoint["model"]
        self.encoder = checkpoint["encoder"]
        self.label_names: list = list(self.encoder.classes_)
        print(f"[Firewall] Classes: {self.label_names}")

        self.preprocessor = LivePreprocessor(warmup_packets=warmup_packets)

        # Capture
        self.capture = LiveCapture(interface=interface, bpf_filter=bpf_filter)

        # Stats
        self.stats = {name: 0 for name in self.label_names}
        self.stats["total"] = 0
        self.stats["warmup"] = 0
        self.start_time = time.time()

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

    def handle_prediction(self, label: str, source_ip: str, raw_df: pd.DataFrame):
        self.stats[label] = self.stats.get(label, 0) + 1

        if label in ATTACK_CLASSES:
            print(f"[BLOCK] ⚠  Attack detected: {label:<25} | src={source_ip or 'unknown'}")
            if self.block and source_ip and source_ip not in self.blocked_ips:
                self.block_ip(source_ip)
        else:
            print(f"[ALLOW] ✓  Normal traffic from {source_ip or 'unknown':<25} | label={label}")

    def block_ip(self, ip: str):
        """Add an iptables DROP rule for the attacking IP."""
        import subprocess
        cmd = f"iptables -I INPUT -s {ip} -j DROP"
        try:
            subprocess.run(cmd.split(), check=True)
            self.blocked_ips.add(ip)
            print(f"[Firewall] iptables rule added: DROP {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[Firewall] Failed to add iptables rule: {e}")

    def print_stats(self):
        elapsed = time.time() - self.start_time
        total = self.stats["total"]
        pps = total / elapsed if elapsed > 0 else 0
        print(f"\n--- Stats ({elapsed:.0f}s | {total} pkts | {pps:.1f} pkt/s) ---")
        for name in self.label_names:
            count = self.stats.get(name, 0)
            pct = 100 * count / total if total else 0
            print(f"  {name:<22} {count:>6}  ({pct:.1f}%)")
        print()

    # ===========================================
    # ---        Main Firewall Pipeline       ---
    # ===========================================

    def run(self):
        """Start capturing and classifying. Blocks until KeyboardInterrupt."""
        self.capture.start()
        print(f"[Firewall] Warming up scaler on first {self.preprocessor.warmup_packets} packets...\n")

        batch_raw: list = []
        batch_dfs: list = []
        last_stats = time.time()

        try:
            while True:
                source_ip, raw_df = self.capture.queue.get()[0], self.capture.queue.get()[1]
                self.stats["total"] += 1

                # Firewall Warmup
                if not self.preprocessor.scaler_fitted:
                    ready = self.preprocessor.add_to_warmup(raw_df)
                    self.stats["warmup"] += 1
                    if ready:
                        print("[Firewall] Warmup complete. Classification started.\n")
                    continue

                batch_raw.append(raw_df)
                batch_dfs.append(raw_df)

                if len(batch_dfs) >= self.batch_size:
                    combined = pd.concat(batch_dfs, ignore_index=True)
                    labels = self.predict(combined)
                    for i, label in enumerate(labels):
                        self.handle_prediction(label, source_ip, batch_raw[i])
                    batch_raw.clear()
                    batch_dfs.clear()

                # Print stats every 5 minutes
                if time.time() - last_stats > 300:
                    self.print_stats()
                    last_stats = time.time()

        except KeyboardInterrupt:
            print("\n[Firewall] Shutting down...")
            self.capture.stop()
            self.print_stats()


#-------------------------------------------------

if __name__ == "__main__":
    fw = Firewall(
        model_path=MODEL_PATH,
        interface="en0",
        bpf_filter=None,
        block=True,
        warmup_packets=100,
        batch_size=1,
    )
    fw.run()
