import time
import joblib
import numpy as np
import xgboost as xgb
from performances import model_performances_multiclass, model_performances_report_generation

MODEL_NAME = "XGBOOST"


# =====================================
# ---    Main utility functions     ---
# =====================================

def save_model(model, encoder, model_name: str) -> None:
    """
    Saves the trained XGBoost model and its LabelEncoder to a joblib file
    inside the ../Models/ directory.

    Input:
    - model:      Trained XGBClassifier.
    - encoder:    Fitted LabelEncoder used to encode/decode class labels.
    - model_name: Base name for the saved file.

    """
    import os
    models_dir = "../Models/"
    os.makedirs(models_dir, exist_ok=True)
    save_path = models_dir + f"{model_name}_classifier.joblib"
    joblib.dump({"model": model, "encoder": encoder}, save_path)
    print(f"Model saved to {save_path}")


def model_train(model, labels_names: list, x: np.ndarray, y: np.ndarray):
    """
    Trains the XGBoost model and evaluates performance on the training set.

    Input:
    - model:        XGBClassifier instance to train.
    - labels_names: List of class name strings (decoded from LabelEncoder).
    - x:            np.ndarray of training features.
    - y:            np.ndarray of encoded training labels (integers).

    Output:
    - model:             The trained XGBClassifier.
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
        model_performances_multiclass(labels_names, y, train_predictions, train_probabilities, "TRAINING", MODEL_NAME)

    model_performances_report_generation(accuracy, precision, recall, f1_macro, f1_micro,
                                         auc, class_report, cm, "TRAINING", MODEL_NAME)

    return model, train_predictions


def model_test(model, labels_names: list, x: np.ndarray, y: np.ndarray):
    """
    Evaluates the trained XGBoost model on the test set and saves a performance report.

    Input:
    - model:        Trained XGBClassifier.
    - labels_names: List of class name strings (decoded from LabelEncoder).
    - x:            np.ndarray of test features.
    - y:            np.ndarray of encoded test labels (integers).

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
        model_performances_multiclass(labels_names, y, test_predictions, test_probabilities, "TESTING", MODEL_NAME)

    model_performances_report_generation(accuracy, precision, recall, f1_macro, f1_micro,
                                         auc, class_report, cm, "TESTING", MODEL_NAME)

    return test_predictions
