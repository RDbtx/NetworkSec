import os
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from model_utilities import model_train, model_test, save_model
from src.model.model_utilities import extract_data

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

    df = extract_data()

    X = df.drop("Label", axis=1).values
    Y = df["Label"].values

    # Split dataset 60 / 40 for train and test
    x_train, x_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, stratify=Y, random_state=42)

    print(f"\nx_train shape: {x_train.shape}")
    print(f"y_train shape: {y_train.shape}")
    print(f"x_test shape:  {x_test.shape}")
    print(f"y_test shape:  {y_test.shape}")

    # Train, Test and Save Model
    trained_model, train_predictions = model_train(xgboost_model, labels_names, x_train, y_train)
    test_predictions = model_test(trained_model, labels_names, x_test, y_test)
    save_model(trained_model, encoder, "XGBOOST")
