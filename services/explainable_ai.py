"""
REALSAFE Explainable AI layer.

SHAP is NOT a separate ML model. It attributes the Random Forest prediction
to individual verification features using TreeSHAP.
"""

import numpy as np
import pandas as pd
import shap
import joblib
import os

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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'random_forest_model.joblib')
LR_MODEL_PATH = os.path.join(BASE_DIR, 'models', 'logistic_regression_model.joblib')

_model = None
_explainer = None
_lr_model = None


def get_or_train_model():
    """Loads the joblib-persisted Random Forest model and prepares SHAP TreeExplainer."""
    global _model, _explainer, _lr_model
    if _model is not None and _explainer is not None:
        return _model, _explainer

    if os.path.exists(MODEL_PATH):
        try:
            _model = joblib.load(MODEL_PATH)
            _explainer = shap.TreeExplainer(_model)
            if os.path.exists(LR_MODEL_PATH):
                _lr_model = joblib.load(LR_MODEL_PATH)
            return _model, _explainer
        except Exception as e:
            print("Warning: Could not load saved model, falling back to training:", e)

    try:
        from ml.train_model import train_and_evaluate
        train_and_evaluate()
        if os.path.exists(MODEL_PATH):
            _model = joblib.load(MODEL_PATH)
            _explainer = shap.TreeExplainer(_model)
            if os.path.exists(LR_MODEL_PATH):
                _lr_model = joblib.load(LR_MODEL_PATH)
            return _model, _explainer
    except Exception as e:
        print("Notice: ML module train_and_evaluate fallback:", e)

    raise RuntimeError(
        "Random Forest model is not available. Run: python ml/train_model.py"
    )


def _extract_class1_shap(shap_vals):
    """Normalize SHAP outputs across shap / sklearn versions to a 1-D class-1 vector."""
    if isinstance(shap_vals, list):
        arr = np.array(shap_vals[1][0])
        return arr
    shap_vals = np.array(shap_vals)
    if shap_vals.ndim == 3:
        return shap_vals[0, :, 1]
    if shap_vals.ndim == 2:
        return shap_vals[0]
    return shap_vals


def explain_property_risk(indicators_dict):
    """
    Computes ML classification and SHAP attributions for a property.

    Returns:
        dict with ml_prediction, suspicious_probability (0-100),
        top_risk_drivers from actual SHAP values, and shap_explanation bullets.
    """
    model, explainer = get_or_train_model()

    row = [1 if indicators_dict.get(feat) else 0 for feat in FEATURE_NAMES]
    df_sample = pd.DataFrame([row], columns=FEATURE_NAMES)

    proba = model.predict_proba(df_sample)[0]
    prob = float(proba[1])
    prediction = 'Suspicious' if prob >= 0.45 else 'Normal'

    shap_vals = explainer.shap_values(df_sample)
    sv = _extract_class1_shap(shap_vals)

    drivers = []
    shap_explanation = []
    for feat, val, shap_weight in zip(FEATURE_NAMES, row, sv):
        weight = float(shap_weight)
        if val == 1 or weight > 0.01:
            drivers.append({
                'feature': feat,
                'label': FEATURE_LABELS.get(feat, feat),
                'impact': weight,
                'active': bool(val == 1)
            })
            if val == 1 and weight > 0:
                shap_explanation.append(
                    f"{FEATURE_LABELS.get(feat, feat)} (SHAP {weight:+.4f})"
                )

    drivers.sort(key=lambda d: d['impact'], reverse=True)
    top_active = [d['label'] for d in drivers if d['active']][:4]

    if prediction == 'Suspicious' and shap_explanation:
        plain = [
            "Explainable AI — SHAP (not a separate model): the Random Forest score is attributed to the following active signals."
        ] + shap_explanation
    elif prediction == 'Suspicious':
        plain = [
            "Explainable AI — SHAP: classified Suspicious; contributing flags: " +
            (", ".join(top_active) if top_active else "combined weak signals")
        ]
    else:
        if shap_explanation:
            plain = [
                "Explainable AI — SHAP: classified Normal. Active signals with smaller push toward suspicion:"
            ] + shap_explanation
        else:
            plain = [
                "Explainable AI — SHAP: classified Normal. No verification flags contributed a material positive SHAP value toward suspicion."
            ]

    lr_probability = None
    lr_prediction = None
    if _lr_model is not None:
        try:
            lr_prob = float(_lr_model.predict_proba(df_sample)[0][1])
            lr_probability = round(lr_prob * 100, 1)
            lr_prediction = 'Suspicious' if lr_prob >= 0.45 else 'Normal'
        except Exception:
            pass

    return {
        'ml_prediction': prediction,
        'suspicious_probability': round(prob * 100, 1),
        'top_risk_drivers': drivers,
        'plain_explanation': plain,
        'shap_top_factors': top_active,
        'lr_prediction': lr_prediction,
        'lr_probability': lr_probability,
        'shap_notice': 'SHAP explains the Random Forest prediction; it is not a separate AI model.'
    }
