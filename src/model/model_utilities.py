import time
import os
import joblib
import numpy as np
import pandas as pd
from performances import model_performances_multiclass, model_performances_report_generation
from sklearn.preprocessing import LabelEncoder

INPUT_PATH = "./output/"

# =====================================
# ---       Label mapping           ---
# =====================================

# Each fine-grained attack label maps to itself — no collapsing.
#
# The previous mapping merged TCP-based and QUIC-based attacks into the same
# class (e.g. "http-flood" and "quic-flood" both → "DDoS-flooding"), which
# caused ~46% of DDoS-flooding packets to be misclassified as Normal because
# the two protocol families occupy completely different regions of the feature
# space after MinMax scaling.
#
# With 11 classes each label has an internally consistent feature distribution
# and the model can learn clean decision boundaries.
LABEL_MAP = {
    "Normal": "Normal",
    "http-flood": "http-flood",
    "quic-flood": "quic-flood",
    "http-loris": "http-loris",
    "quic-loris": "quic-loris",
    "fuzzing": "fuzzing",
    "quic-enc": "quic-enc",
    "http-smuggle": "http-smuggle",
    "http2-concurrent": "http2-concurrent",
    "http2-pause": "http2-pause",
}


# Note: http-stream is excluded — too few samples, dropped from training.
# The 10 entries above (Normal + 9 attacks) are the active classes.


# =====================================
# ---    Main utility functions     ---
# =====================================

def extract_data():
    input_csv = os.path.join(INPUT_PATH, "pcap-all-final.csv")
    print("Loading dataset...")
    df = pd.read_csv(input_csv, low_memory=False)
    df["Label"] = df["Label"].map(LABEL_MAP)
    unmapped = df["Label"].isnull().sum()
    if unmapped > 0:
        print(f"Warning: {unmapped} rows had unmapped labels and will be dropped.")
        df = df.dropna(subset=["Label"])

    print("\nClass distributions:")
    print(df["Label"].value_counts())
    encoder = LabelEncoder()
    df["Label"] = encoder.fit_transform(df["Label"])
    labels_names = list(encoder.classes_)
    print(f"\nClasses: {labels_names}")
    return df, encoder, labels_names


def save_model(model, encoder, model_name: str) -> None:
    """
    Saves the trained model and its LabelEncoder to a joblib file
    inside the output/saved_models/ directory.

    Input:
    - model: Trained classifier.
    - encoder: Fitted LabelEncoder used to encode/decode class labels.
    - model_name: Base name for the saved file.
    """
    models_dir = "output/saved_models/"
    os.makedirs(models_dir, exist_ok=True)
    save_path = models_dir + f"{model_name}_classifier.joblib"
    joblib.dump({"model": model, "encoder": encoder}, save_path)
    print(f"Model saved to {save_path}")


def model_train(model, labels_names: list, x: np.ndarray, y: np.ndarray, model_name):
    """
    Trains the model and evaluates performance on the training set.

    Inputs:
    - model: Classifier instance to train.
    - labels_names: List of class name strings (decoded from LabelEncoder).
    - x: np.ndarray of training features.
    - y: np.ndarray of encoded training labels (integers).

    Outputs:
    - model: The trained classifier.
    - train_predictions: np.ndarray of predicted class indices on the training set.
    """
    print("\n----MODEL TRAINING STARTED----")
    print("Training model...")
    train_time = time.time()
    model.fit(x, y)
    print(f"Training time: {(time.time() - train_time):.1f} s")
    print("----TRAINING COMPLETED----\n")

    print("Computing training predictions...")
    pred_time = time.time()
    train_predictions = model.predict(x)
    train_probabilities = model.predict_proba(x)
    print(f"Prediction time: {(time.time() - pred_time):.1f} s")

    accuracy, precision, recall, f1_macro, f1_micro, auc, class_report, cm = \
        model_performances_multiclass(labels_names, y, train_predictions, train_probabilities, "TRAINING", model_name)

    model_performances_report_generation(accuracy, precision, recall, f1_macro, f1_micro,
                                         auc, class_report, cm, "TRAINING", model_name)

    return model, train_predictions


def model_test(model, labels_names: list, x: np.ndarray, y: np.ndarray, model_name: str):
    """
    Evaluates the trained model on the test set and saves a performance report.

    Input:
    - model: Trained model.
    - labels_names: List of class name strings (decoded from LabelEncoder).
    - x: np.ndarray of test features.
    - y: np.ndarray of encoded test labels (integers).

    Output:
    - test_predictions: np.ndarray of predicted class indices on the test set.
    """
    print("\n----MODEL TESTING----")
    print("Testing model...")
    test_time = time.time()
    test_predictions = model.predict(x)
    test_probabilities = model.predict_proba(x)
    print(f"Test time: {(time.time() - test_time):.1f} s")
    print("----TESTING COMPLETED----\n")

    accuracy, precision, recall, f1_macro, f1_micro, auc, class_report, cm = \
        model_performances_multiclass(labels_names, y, test_predictions, test_probabilities, "TESTING", model_name)

    model_performances_report_generation(accuracy, precision, recall, f1_macro, f1_micro,
                                         auc, class_report, cm, "TESTING", model_name)

    return test_predictions
