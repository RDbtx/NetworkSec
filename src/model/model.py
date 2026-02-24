import os
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from model_utilities import model_train, model_test, save_model

# =====================================
# ---       Label mapping           ---
# =====================================

LABEL_MAP = {
    "Normal":           "Normal",
    "http-flood":       "DDoS-flooding",
    "http-stream":      "DDoS-flooding",
    "quic-flood":       "DDoS-flooding",
    "http-loris":       "DDoS-loris",
    "quic-loris":       "DDoS-loris",
    "fuzzing":          "Transport-layer",
    "quic-enc":         "Transport-layer",
    "http-smuggle":     "HTTP/2-attacks",
    "http2-concurrent": "HTTP/2-attacks",
    "http2-pause":      "HTTP/2-attacks",
}

# =====================================
# ---       Model declaration       ---
# =====================================

xgboost_model = xgb.XGBClassifier(
    objective="multi:softmax",
    num_class=5,
    n_estimators=500,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric="mlogloss",
    n_jobs=-1,
    random_state=42
)

# =====================================
# ---       Main Execution          ---
# =====================================

if __name__ == "__main__":
    INPUT_PATH = os.path.join(Path(__file__).resolve().parent.parent, "output", "pcap-all-final.csv")

    # --- Load and remap labels ---
    print("Loading dataset...")
    df = pd.read_csv(INPUT_PATH, low_memory=False)
    df["Label"] = df["Label"].map(LABEL_MAP)

    unmapped = df["Label"].isnull().sum()
    if unmapped > 0:
        print(f"Warning: {unmapped} rows had unmapped labels and will be dropped.")
        df = df.dropna(subset=["Label"])

    print("\nClass distribution:")
    print(df["Label"].value_counts())

    # --- Encode labels ---
    encoder = LabelEncoder()
    df["Label"] = encoder.fit_transform(df["Label"])
    labels_names = list(encoder.classes_)
    print(f"\nClasses: {labels_names}")

    # --- Split features and labels ---
    X = df.drop("Label", axis=1).values
    y = df["Label"].values

    # Stratified 60/40 split as per the paper
    x_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.4, stratify=y, random_state=42)

    print(f"\nx_train shape: {x_train.shape}")
    print(f"y_train shape: {y_train.shape}")
    print(f"x_test shape:  {x_test.shape}")
    print(f"y_test shape:  {y_test.shape}")

    # --- Train and evaluate ---
    trained_model, train_predictions = model_train(xgboost_model, labels_names, x_train, y_train)
    test_predictions = model_test(trained_model, labels_names, x_test, y_test)

    # --- Save model ---
    save_model(trained_model, encoder, "XGBOOST")