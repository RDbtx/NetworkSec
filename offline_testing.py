"""
offline_testing.py
==================
Runs the trained classifier against a raw PCAP file.

Uses tshark (via FileCapture from data_extraction.py) as the sole extraction
backend — validated at 100% match against the training CSVs.

Pipeline
--------
  1. FileCapture iterates the PCAP using tshark, yielding one
     (source_ip, raw_df) per packet — identical format to training data.
  2. OfflinePreprocessor applies the same four steps as scaling.py:
       fill_missing -> resolve_compound -> one_hot_encode -> minmax_scale
  3. The preprocessed row is fed to the trained classifier.
"""

LABEL_MAP = {
    "Normal": "Normal",
    "http-flood": "DDoS-flooding",
    "http-stream": "DDoS-flooding",
    "quic-flood": "DDoS-flooding",
    "http-loris": "DDoS-loris",
    "quic-loris": "DDoS-loris",
    "fuzzing": "Transport-layer",
    "quic-enc": "Transport-layer",
    "http-smuggle": "HTTP/2-attacks",
    "http2-concurrent": "HTTP/2-attacks",
    "http2-pause": "HTTP/2-attacks",
}


from pathlib import Path

import joblib
import pandas as pd

from src.model.preprocessing.scaling import FLAG_COLS, TO_SCALE_COLUMNS
from src.firewall.data_extraction import FileCapture, load_pcap_as_dataframe

# ── paths — edit these to match your layout ──────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent
PCAP_PATH    = BASE_DIR / "src/model/dataset/1-http-flood/pcap1-caddy.pcap"
MODEL_PATH   = BASE_DIR / "src/firewall/model/Blackwall.joblib"
SCALER_PATH  = BASE_DIR / "src/firewall/model/scaler.joblib"
DATASET_PATH = BASE_DIR / "src/model/output/pcap-all-final.csv"
KEYLOG_PATH  = BASE_DIR / "src/model/dataset/ssl keys/all.txt"


# =============================================================================
#  OfflinePreprocessor — mirrors scaling.py exactly
# =============================================================================

class OfflinePreprocessor:
    """
    Replicates the four preprocessing steps of scaling.py so that each raw
    tshark row is transformed into the same feature space the model was
    trained on.

    Parameters
    ----------
    dataset_csv   : path to pcap-all-final.csv — read header-only to get the
                    exact post-OHE column set the model expects
    scaler_joblib : path to scaler.joblib saved by scaling.py
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
        """FLAG_COLS NaN -> -1 (distinct OHE category); everything else -> 0."""
        for col in FLAG_COLS:
            if col in df.columns:
                df[col] = df[col].fillna(-1)
        return df.fillna(0)

    def resolve_compound(self, df: pd.DataFrame) -> pd.DataFrame:
        """Evaluate arithmetic strings like '3+8+5+1' -> 17.0"""
        obj_cols = [c for c in df.select_dtypes(include=["object", "string"]).columns
                    if c != "Label"]
        for col in obj_cols:
            def _safe_eval(v: object, _col: str = col) -> object:
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
        """One-hot encode FLAG_COLS then align to training column set."""
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


# =============================================================================
#  Main test runner
# =============================================================================

def run_static_test(
    pcap_path: Path    = PCAP_PATH,
    model_path: Path   = MODEL_PATH,
    scaler_path: Path  = SCALER_PATH,
    dataset_path: Path = DATASET_PATH,
    keylog_path: Path  = KEYLOG_PATH,
) -> None:
    checkpoint  = joblib.load(model_path)
    model       = checkpoint["model"]
    encoder     = checkpoint["encoder"]
    label_names = list(encoder.classes_)

    preprocessor = OfflinePreprocessor(
        dataset_csv=dataset_path,
        scaler_joblib=scaler_path,
    )

    keylog = str(keylog_path) if keylog_path.exists() else None

    print(f"PCAP_PATH    = {pcap_path}")
    print(f"MODEL_PATH   = {model_path}")
    print(f"SCALER_PATH  = {scaler_path}")
    print(f"DATASET_PATH = {dataset_path}")
    print(f"KEYLOG_PATH  = {keylog or '(not found — TLS will not be decrypted)'}")
    print(f"OHE columns  = {len(preprocessor.ohe_columns)}")

    seen = classified = errors = 0
    preds: dict[str, int] = {}

    for source_ip, df in FileCapture(pcap_path, keylog=keylog):
        seen += 1
        try:
            processed = preprocessor.preprocess(df)
            X = processed.values.astype(float)
            idx   = int(model.predict(X)[0])
            label = label_names[idx]
            preds[label] = preds.get(label, 0) + 1
            classified += 1
        except Exception as exc:
            errors += 1
            if errors <= 5:
                print(f"[PKT {seen}] error: {exc}")

    print("\n=== Summary ===")
    print(f"Packets seen:       {seen}")
    print(f"Packets classified: {classified}")
    print(f"Errors:             {errors}")
    print("\nPrediction counts:")
    for label, count in sorted(preds.items(), key=lambda x: -x[1]):
        pct = 100 * count / classified if classified else 0
        print(f"  {label:<30} {count:>6}  ({pct:.1f}%)")


def diagnose_vs_labels(
    pcap_path: Path  = PCAP_PATH,
    label_csv: Path  = PCAP_PATH.parent / (PCAP_PATH.stem + "-l.csv"),
    scaler_path: Path = SCALER_PATH,
    dataset_path: Path = DATASET_PATH,
    keylog_path: Path  = KEYLOG_PATH,
    model_path: Path   = MODEL_PATH,
) -> None:
    """
    Load the raw features from the PCAP, attach the ground-truth labels from
    the labeled CSV, then check:
      1. Feature presence per class — are attack packets arriving with their
         distinguishing features populated, or mostly null?
      2. Prediction accuracy — how many attack packets does the model correctly
         identify vs misclassify?

    This is the primary tool for understanding why predictions diverge from
    ground truth.
    """

    keylog = str(keylog_path) if keylog_path.exists() else None

    # ── load raw features ─────────────────────────────────────────────────────
    print(f"Loading PCAP: {pcap_path.name}")
    raw_df, source_ips = load_pcap_as_dataframe(pcap_path, keylog=keylog)

    # ── load ground-truth labels ──────────────────────────────────────────────
    print(f"Loading labels: {label_csv.name}")
    labels_df = pd.read_csv(label_csv, usecols=["Label"], on_bad_lines="skip")

    if len(raw_df) != len(labels_df):
        print(f"WARNING: row count mismatch — PCAP={len(raw_df)}, CSV={len(labels_df)}")
        print("Truncating to shorter length. Results may be unreliable.")
        n = min(len(raw_df), len(labels_df))
        raw_df    = raw_df.iloc[:n].reset_index(drop=True)
        labels_df = labels_df.iloc[:n].reset_index(drop=True)

    raw_df["Label"]       = labels_df["Label"].values
    raw_df["Label_mapped"] = raw_df["Label"].map(LABEL_MAP)

    # ── 1. feature presence per class ────────────────────────────────────────
    print("\n=== Feature presence (non-null count) per class ===")
    feat_cols = [c for c in raw_df.columns if c not in ("Label", "Label_mapped")]
    for cls in raw_df["Label"].unique():
        subset = raw_df[raw_df["Label"] == cls][feat_cols]
        present = subset.notna().sum()
        top = present[present > 0].sort_values(ascending=False).head(10)
        print(f"\n  [{cls}]  ({len(subset)} packets)")
        for feat, cnt in top.items():
            print(f"    {feat:<45} {cnt:>6} / {len(subset)}")

    # ── 2. prediction accuracy vs ground truth ────────────────────────────────
    print("\n=== Prediction accuracy vs ground truth ===")
    preprocessor = OfflinePreprocessor(dataset_csv=dataset_path, scaler_joblib=scaler_path)
    checkpoint   = joblib.load(model_path)
    model        = checkpoint["model"]
    encoder      = checkpoint["encoder"]
    label_names  = list(encoder.classes_)

    processed = preprocessor.preprocess(raw_df.drop(columns=["Label", "Label_mapped"]))
    X         = processed.values.astype(float)
    indices   = model.predict(X)
    predicted = [label_names[int(i)] for i in indices]

    raw_df["Predicted"] = predicted

    # confusion: ground-truth mapped label vs predicted label
    from collections import Counter
    for true_cls in sorted(raw_df["Label_mapped"].unique()):
        subset = raw_df[raw_df["Label_mapped"] == true_cls]
        pred_counts = Counter(subset["Predicted"])
        total = len(subset)
        print(f"\n  True: {true_cls}  ({total} packets)")
        for pred_label, cnt in pred_counts.most_common():
            pct = 100 * cnt / total
            marker = "✓" if pred_label == true_cls else "✗"
            print(f"    {marker} Predicted {pred_label:<30} {cnt:>6}  ({pct:.1f}%)")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "diagnose":
        diagnose_vs_labels()
    else:
        run_static_test()