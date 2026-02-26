from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, accuracy_score, classification_report, \
    precision_score, recall_score, f1_score, roc_auc_score
import matplotlib.pyplot as plt
import numpy as np
import os

XGBOOST_RESULT_DIR = "output/results/xgboost/"


def to_class_indices(y: np.ndarray) -> np.ndarray:
    """
    Converts a 2D one-hot encoded array into 1D class indices for metric computation.
    If already 1D, returns as-is.

    Input:
    - y: np.ndarray containing samples and their labels (1D or 2D one-hot).

    Output:
    - y: 1D np.ndarray of class indices.
    """
    y = np.asarray(y)
    if y.ndim == 2 and y.shape[1] > 1:
        return y.argmax(axis=1)
    return y


def model_performances_report_generation(accuracy, precision, recall, f1_macro, f1_micro,
                                         auc, class_report, conf_matrix,
                                         scenario: str, model_name: str) -> None:
    """
    Generates a text performance report and saves it to the Results directory.

    Input:
    - accuracy:    Accuracy score.
    - precision:   Macro precision score.
    - recall:      Macro recall score.
    - f1_macro:    Macro F1 score.
    - f1_micro:    Micro F1 score.
    - auc:         Macro OvR AUC score.
    - class_report: Per-class classification report string.
    - conf_matrix: Confusion matrix np.ndarray.
    - scenario:    'TRAINING' or 'TESTING'.
    - model_name:  Name of the model (used for file naming).

    """
    report_dir = os.path.join(XGBOOST_RESULT_DIR, "reports")
    os.makedirs(report_dir, exist_ok=True)

    print("Performance Report generation...")
    report_str = [
        f"\n----{model_name} {scenario} PERFORMANCES----",
        f"Accuracy:      {accuracy:.4f}",
        f"Precision:     {precision:.4f}",
        f"Recall:        {recall:.4f}",
        f"F1 micro:      {f1_micro:.4f}",
        f"F1 macro:      {f1_macro:.4f}",
        f"AUC (macro):   {auc:.4f}",
        "\nClassification Report:\n",
        class_report,
        "\nConfusion Matrix:\n",
        np.array2string(conf_matrix)
    ]
    output = "\n".join(report_str)

    file_path = os.path.join(report_dir, f"{model_name}_{scenario}_performances_report.txt")
    with open(file_path, "w") as f:
        f.write(output)
    print(f"Results saved to {file_path}")


def model_performances_multiclass(labels_names: list, y_true: np.ndarray, y_pred: np.ndarray,
                                  y_prob: np.ndarray, scenario: str, model_name: str):
    """
    Computes and displays all performance metrics for a multiclass classifier,
    including a confusion matrix plot saved to disk.

    Input:
    - labels_names: List of class name strings for display.
    - y_true:       1D np.ndarray of true class indices.
    - y_pred:       1D np.ndarray of predicted class indices.
    - y_prob:       2D np.ndarray of predicted probabilities (for AUC).
    - scenario:     'TRAINING' or 'TESTING'.
    - model_name:   Name of the model.

    Output:
    - accuracy, precision, recall, f1_macro, f1_micro, auc, class_report, cm
    """
    y_true = to_class_indices(y_true)
    y_pred = to_class_indices(y_pred)

    n_classes = len(labels_names)
    all_labels = np.arange(n_classes)
    samples = len(y_true)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average='macro', zero_division=0)
    recall = recall_score(y_true, y_pred, average='macro', zero_division=0)
    f1_micro = f1_score(y_true, y_pred, average='micro', zero_division=0)
    f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
    auc = roc_auc_score(y_true, y_prob, multi_class='ovr', average='macro')
    cm = confusion_matrix(y_true, y_pred, labels=all_labels)
    class_report = classification_report(y_true, y_pred, labels=all_labels,
                                         target_names=labels_names, zero_division=0)

    print(f"\n----{model_name} {scenario} PERFORMANCES----")
    print(f"Accuracy:    {accuracy:.4f}")
    print(f"Precision:   {precision:.4f}")
    print(f"Recall:      {recall:.4f}")
    print(f"F1 (micro):  {f1_micro:.4f}")
    print(f"F1 (macro):  {f1_macro:.4f}")
    print(f"AUC (macro): {auc:.4f}")
    print("\nClassification Report:")
    print(class_report)

    # Confusion matrix plot
    fig, ax = plt.subplots(figsize=(10, 8))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels_names)
    disp.plot(ax=ax, cmap='Blues', include_values=True, xticks_rotation=45)
    plt.title(f"{model_name} {scenario} Confusion Matrix — {n_classes} Classes, {samples} Samples",
              fontsize=14, pad=15)
    plt.xlabel("Predicted Label", fontsize=12)
    plt.ylabel("True Label", fontsize=12)
    plt.tight_layout()

    os.makedirs(XGBOOST_RESULT_DIR, exist_ok=True)
    plot_path = os.path.join(XGBOOST_RESULT_DIR, f"{model_name}_{scenario}_conf_matrix.png")
    plt.savefig(plot_path)
    plt.show()
    print(f"Confusion matrix saved to {plot_path}")

    return accuracy, precision, recall, f1_macro, f1_micro, auc, class_report, cm
