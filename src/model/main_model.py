import xgboost as xgb
from sklearn.model_selection import train_test_split
from model_utilities import model_train, model_test, save_model, extract_data
from sklearn.ensemble import RandomForestClassifier
import lightgbm as lgb

# =====================================
# ---       Models declaration      ---
# =====================================

# LightGBM
lgbm_multi = lgb.LGBMClassifier(
    objective='multiclass',
    num_class=10,  # 10 classes: Normal + 9 attack types
    n_estimators=500,
    learning_rate=0.05,
    max_depth=7,
    num_leaves=63,
    subsample=0.8,
    colsample_bytree=0.8,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
    verbose=0,
)

# XGBoost
xgboost_model = xgb.XGBClassifier(
    objective="multi:softmax",
    num_class=10,  # 10 classes: Normal + 9 attack types
    n_estimators=500,
    learning_rate=0.05,
    max_depth=7,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="mlogloss",
    n_jobs=-1,
    random_state=42
)

# Random Forest
random_forest = RandomForestClassifier(
    n_estimators=500,
    max_depth=7,
    min_samples_split=20,
    min_samples_leaf=10,
    max_features="sqrt",
    class_weight="balanced_subsample",
    random_state=42,
    n_jobs=-1
)

# =====================================
# ---       Main Execution          ---
# =====================================

if __name__ == "__main__":
    df, encoder, labels_names = extract_data()

    X = df.drop("Label", axis=1).values
    Y = df["Label"].values

    # Split dataset 60 / 40 for train and test
    x_train, x_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, stratify=Y, random_state=42)

    print(f"\nx_train shape: {x_train.shape}")
    print(f"y_train shape: {y_train.shape}")
    print(f"x_test shape:  {x_test.shape}")
    print(f"y_test shape:  {y_test.shape}")

    # Train, Test and Save Model
    # lightboost_trained_model, lightboost_train_predictions = model_train(lgbm_multi, labels_names, x_train, y_train, "LGB_Blackwall")
    boost_trained_model, boost_train_predictions = model_train(xgboost_model, labels_names, x_train, y_train,
                                                               "XGB_Blackwall")
    # random_trained_model, random_train_predictions = model_train(random_forest, labels_names, x_train, y_train, "RF_Blackwall")

    # lightboost_test_predictions = model_test(lightboost_trained_model, labels_names, x_test, y_test, "LGB_Blackwall")
    boost_test_predictions = model_test(boost_trained_model, labels_names, x_test, y_test, "XGB_Blackwall")
    # random_test_predictions = model_test(random_trained_model, labels_names, x_test, y_test, "RF_Blackwall")

    # save_model(lightboost_trained_model, encoder, "LGB_Blackwall")
    save_model(boost_trained_model, encoder, "XGB_Blackwall")
    # save_model(random_trained_model, encoder, "RF_Blackwall")
