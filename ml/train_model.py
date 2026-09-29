"""
REALSAFE Machine Learning Training & Evaluation Pipeline
Trains primary RandomForestClassifier and baseline LogisticRegression models
using an 80% train / 20% test stratified split on the synthetic property fraud dataset.
Computes and stores authentic test-set performance metrics (Accuracy, Precision, Recall, F1, Confusion Matrix).
Saves models with joblib and records model comparison into SQLite model_metrics table.
Prepares SHAP TreeExplainer for post-prediction explainability.
"""

import os
import sys
import json
import sqlite3
from datetime import datetime
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)
import shap

# Set paths before local imports
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from models.database import init_db

DATA_PATH = os.path.join(BASE_DIR, 'data', 'synthetic_property_fraud_dataset.csv')
DB_PATH = os.path.join(BASE_DIR, 'database', 'realsafe.db')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

FEATURE_NAMES = [
    'owner_mismatch',
    'survey_mismatch',
    'area_mismatch',
    'duplicate_property',
    'hash_mismatch',
    'ownership_conflict',
    'suspicious_transfer',
    'missing_document'
]

FEATURE_LABELS = {
    'owner_mismatch': 'Owner Name Discrepancy',
    'survey_mismatch': 'Survey Number Discrepancy',
    'area_mismatch': 'Land Area Variance',
    'duplicate_property': 'Duplicate Property Cluster',
    'hash_mismatch': 'Document Hash Tamper Flag',
    'ownership_conflict': 'Title Chain Timeline Gap',
    'suspicious_transfer': 'High Velocity Transfers',
    'missing_document': 'Incomplete Primary Title Vault'
}

def load_and_preprocess_data():
    """Loads and prepares the 8 fraud features and target label from dataset."""
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}. Run generate_dataset.py first.")

    df = pd.read_csv(DATA_PATH)
    print(f"Loaded dataset with {len(df)} records from {DATA_PATH}")

    # Map column names to standard feature names
    col_mapping = {
        'ownership_history_conflict': 'ownership_conflict',
        'suspicious_transfer_pattern': 'suspicious_transfer'
    }
    for old_col, new_col in col_mapping.items():
        if old_col in df.columns and new_col not in df.columns:
            df[new_col] = df[old_col]

    # Validate that all 8 features exist
    for f in FEATURE_NAMES:
        if f not in df.columns:
            raise KeyError(f"Required feature column '{f}' missing from dataset.")

    if 'fraud_label' not in df.columns:
        raise KeyError("Required label column 'fraud_label' missing from dataset.")

    X = df[FEATURE_NAMES].astype(int)
    y = df['fraud_label'].astype(int)

    return X, y, df

def train_and_evaluate():
    """Executes the full training, evaluation, comparison, and persistence pipeline."""
    X, y, full_df = load_and_preprocess_data()

    print("\nDataset Summary:")
    print(f"Total Samples    : {len(X)}")
    print(f"Features ({len(FEATURE_NAMES)}) : {', '.join(FEATURE_NAMES)}")
    print(f"Class 0 (Normal) : {(y == 0).sum()} ({(y == 0).mean():.1%})")
    print(f"Class 1 (Fraud)  : {(y == 1).sum()} ({(y == 1).mean():.1%})")

    # 1. Stratified 80% Train / 20% Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"\nTrain Set Size: {len(X_train)} samples")
    print(f"Test Set Size : {len(X_test)} samples (evaluated exclusively for honest metrics)")

    # 2. Train Baseline Model: Logistic Regression
    print("\nTraining Baseline: Logistic Regression...")
    lr_model = LogisticRegression(random_state=42, max_iter=1000, class_weight='balanced')
    lr_model.fit(X_train, y_train)
    lr_y_pred = lr_model.predict(X_test)

    lr_acc = float(accuracy_score(y_test, lr_y_pred))
    lr_prec = float(precision_score(y_test, lr_y_pred, zero_division=0))
    lr_rec = float(recall_score(y_test, lr_y_pred, zero_division=0))
    lr_f1 = float(f1_score(y_test, lr_y_pred, zero_division=0))
    lr_cm = confusion_matrix(y_test, lr_y_pred).tolist()

    # 3. Train Primary Model: Random Forest Classifier
    print("Training Primary Model: Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight='balanced'
    )
    rf_model.fit(X_train, y_train)
    rf_y_pred = rf_model.predict(X_test)

    rf_acc = float(accuracy_score(y_test, rf_y_pred))
    rf_prec = float(precision_score(y_test, rf_y_pred, zero_division=0))
    rf_rec = float(recall_score(y_test, rf_y_pred, zero_division=0))
    rf_f1 = float(f1_score(y_test, rf_y_pred, zero_division=0))
    rf_cm = confusion_matrix(y_test, rf_y_pred).tolist()

    # 4. Model Comparison Display
    print("\n" + "=" * 65)
    print("        MODEL PERFORMANCE COMPARISON (ON TEST SET ONLY)")
    print("=" * 65)
    print(f"{'Metric':<18} | {'Random Forest (Primary)':<24} | {'Logistic Reg (Baseline)':<22}")
    print("-" * 65)
    print(f"{'Accuracy':<18} | {rf_acc * 100:>21.2f}% | {lr_acc * 100:>20.2f}%")
    print(f"{'Precision':<18} | {rf_prec * 100:>21.2f}% | {lr_prec * 100:>20.2f}%")
    print(f"{'Recall':<18} | {rf_rec * 100:>21.2f}% | {lr_rec * 100:>20.2f}%")
    print(f"{'F1-Score':<18} | {rf_f1 * 100:>21.2f}% | {lr_f1 * 100:>20.2f}%")
    print("-" * 65)
    print(f"Confusion Matrix (RF) : TN={rf_cm[0][0]}, FP={rf_cm[0][1]}, FN={rf_cm[1][0]}, TP={rf_cm[1][1]}")
    print(f"Confusion Matrix (LR) : TN={lr_cm[0][0]}, FP={lr_cm[0][1]}, FN={lr_cm[1][0]}, TP={lr_cm[1][1]}")
    print("=" * 65)

    selection_rationale = (
        "Random Forest is chosen as the primary classification model because decision trees "
        "model non-linear combinatorial interactions between fraud signals (e.g. rapid flips combined with "
        "area variance or hash alteration) and natively integrate with TreeSHAP for game-theoretic local explainability."
    )
    print(f"\nSelection Rationale: {selection_rationale}")

    # 5. Initialize and Validate SHAP TreeExplainer
    print("\nInitializing SHAP TreeExplainer for Random Forest...")
    explainer = shap.TreeExplainer(rf_model)
    # Validate with a test sample
    sample_vec = pd.DataFrame([[1, 0, 0, 0, 1, 0, 0, 0]], columns=FEATURE_NAMES)
    sv = explainer.shap_values(sample_vec)
    print(f"SHAP Explainer successfully verified. Explainer base value: {explainer.expected_value}")

    # 6. Model Persistence
    os.makedirs(MODELS_DIR, exist_ok=True)
    rf_path = os.path.join(MODELS_DIR, 'random_forest_model.joblib')
    lr_path = os.path.join(MODELS_DIR, 'logistic_regression_model.joblib')
    joblib.dump(rf_model, rf_path)
    joblib.dump(lr_model, lr_path)
    print(f"\nModels saved:\n  - {rf_path}\n  - {lr_path}")

    # 7. Metadata and Metrics Serialization
    model_version = "REALSAFE-RF-v1.0"
    training_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    metadata = {
        'model_name': 'Random Forest Classifier',
        'model_version': model_version,
        'training_date': training_date,
        'dataset_size': len(full_df),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'feature_count': len(FEATURE_NAMES),
        'features': FEATURE_NAMES,
        'feature_labels': FEATURE_LABELS,
        'selection_rationale': selection_rationale,
        'random_forest': {
            'model_name': 'Random Forest Classifier',
            'accuracy': round(rf_acc, 4),
            'precision': round(rf_prec, 4),
            'recall': round(rf_rec, 4),
            'f1_score': round(rf_f1, 4),
            'confusion_matrix': rf_cm,
            'parameters': {'n_estimators': 100, 'class_weight': 'balanced', 'random_state': 42},
            'notes': 'Metrics computed on held-out 20% test set only. Dataset is synthetic/demo.'
        },
        'logistic_regression': {
            'model_name': 'Logistic Regression Baseline',
            'accuracy': round(lr_acc, 4),
            'precision': round(lr_prec, 4),
            'recall': round(lr_rec, 4),
            'f1_score': round(lr_f1, 4),
            'confusion_matrix': lr_cm,
            'parameters': {'max_iter': 1000, 'class_weight': 'balanced', 'random_state': 42}
        }
    }

    meta_path = os.path.join(MODELS_DIR, 'model_metadata.json')
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata and metrics saved to: {meta_path}")

    feature_info = {
        'feature_order': FEATURE_NAMES,
        'feature_labels': FEATURE_LABELS,
        'label_column': 'fraud_label',
        'dataset_path': DATA_PATH,
        'dataset_notice': 'Synthetic development/demo dataset. Not official government fraud data.',
        'train_test_split': {'test_size': 0.20, 'random_state': 42, 'stratify': True}
    }
    feat_path = os.path.join(MODELS_DIR, 'feature_info.json')
    with open(feat_path, 'w', encoding='utf-8') as f:
        json.dump(feature_info, f, indent=2)
    print(f"Feature information saved to: {feat_path}")

    # 8. Store Metrics in SQLite Database
    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # Clean prior entries for clear presentation
        cur.execute("DELETE FROM model_metrics")

        # Insert Random Forest metrics
        cur.execute("""
            INSERT INTO model_metrics (
                model_name, model_version, training_date, dataset_size, feature_count,
                accuracy, precision, recall, f1_score, confusion_matrix, is_primary, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            'Random Forest Classifier',
            model_version,
            training_date,
            len(full_df),
            len(FEATURE_NAMES),
            round(rf_acc * 100, 2),
            round(rf_prec * 100, 2),
            round(rf_rec * 100, 2),
            round(rf_f1 * 100, 2),
            json.dumps(rf_cm),
            selection_rationale
        ))

        # Insert Logistic Regression metrics
        cur.execute("""
            INSERT INTO model_metrics (
                model_name, model_version, training_date, dataset_size, feature_count,
                accuracy, precision, recall, f1_score, confusion_matrix, is_primary, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (
            'Logistic Regression Baseline',
            'REALSAFE-LR-v1.0',
            training_date,
            len(full_df),
            len(FEATURE_NAMES),
            round(lr_acc * 100, 2),
            round(lr_prec * 100, 2),
            round(lr_rec * 100, 2),
            round(lr_f1 * 100, 2),
            json.dumps(lr_cm),
            "Linear baseline reference model."
        ))

        conn.commit()
        conn.close()
        print("Metrics successfully persisted to SQLite 'model_metrics' table.")
    except Exception as e:
        print("Notice: Could not write metrics to SQLite (table might need init):", e)

    return metadata

if __name__ == '__main__':
    train_and_evaluate()
