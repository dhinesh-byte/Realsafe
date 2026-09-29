"""
REALSAFE Automated Test & Verification Suite
Tests core fraud-detection modules:
- Document SHA-256 Hashing & Tamper Detection
- Cross-Document Mismatch Detection
- Duplicate Property Detection
- Rule-Based Risk Engine
- Explainable AI & SHAP Integration
- End-to-End Property Verification Workflow
"""

import sys
import os

# Ensure package path is resolved
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.hash_service import compute_sha256_for_file, verify_document_hash, simulate_tampering
from services.duplicate_detector import find_duplicates_for_property
from services.risk_engine import calculate_property_risk
from services.explainable_ai import explain_property_risk
from services.document_verifier import run_full_property_verification
from models.database import get_db_connection

def test_hash_tampering():
    print("\n--- TEST 1: Hash Tamper Detection ---")
    test_file = os.path.join(os.path.dirname(__file__), 'uploads', 'RS-PROP-0001_sale_deed.txt')
    clean_hash = compute_sha256_for_file(test_file)
    assert clean_hash is not None, "Failed to compute clean hash"
    
    # Check verification with clean hash
    res = verify_document_hash(test_file, clean_hash)
    assert res['is_valid'] is True, "Clean hash should be valid"
    assert 'VERIFIED' in res['status'].upper()
    
    # Check with tampered/altered hash
    tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    tampered_res = verify_document_hash(test_file, tampered_hash)
    assert tampered_res['is_valid'] is False, "Altered hash should fail"
    assert 'TAMPER' in tampered_res['status'].upper() or 'MISMATCH' in tampered_res['status'].upper()
    print("PASS: Document Hash Tamper Detection works as expected.")

def test_duplicate_detection():
    print("\n--- TEST 2: Duplicate Property Detection ---")
    dup_res = find_duplicates_for_property('RS-PROP-0023')
    assert dup_res['is_duplicate'] is True, "RS-PROP-0023 should be flagged as duplicate"
    matched_ids = [m['property_id'] for m in dup_res['matches']]
    assert 'RS-PROP-0087' in matched_ids, f"Expected RS-PROP-0087 in duplicates, got {matched_ids}"
    print(f"PASS: Detected duplicate between RS-PROP-0023 and {matched_ids}.")

def test_risk_scoring():
    print("\n--- TEST 3: Rule-Based Risk Engine (4 Tiers) ---")
    # 1. Low Risk Case (0-29)
    low = calculate_property_risk({})
    assert low['score'] == 0
    assert low['risk_level'] == 'Low Risk'

    # 2. Medium Risk Case (30-59)
    med = calculate_property_risk({'area_mismatch': True, 'suspicious_transfer': True})
    assert med['score'] == 30
    assert med['risk_level'] == 'Medium Risk'

    # 3. High Risk Case (60-79)
    high = calculate_property_risk({
        'owner_mismatch': True,
        'survey_mismatch': True,
        'missing_document': True
    })
    # 25 + 25 + 10 = 60
    assert high['score'] == 60
    assert high['risk_level'] == 'High Risk'

    # 4. Critical Risk Case (80-100)
    critical = calculate_property_risk({
        'owner_mismatch': True,
        'survey_mismatch': True,
        'hash_mismatch': True
    })
    # 25 + 25 + 30 = 80
    assert critical['score'] == 80
    assert critical['risk_level'] == 'Critical Risk'
    assert len(critical['reasons']) == 3
    print(f"PASS: 4-Tier Risk Engine validated: Low (0), Med (30), High (60), Critical (80).")

def test_explainable_ai():
    print("\n--- TEST 4: Explainable AI & SHAP Integration ---")
    explanation = explain_property_risk({
        'owner_mismatch': True,
        'survey_mismatch': True,
        'duplicate_property': True
    })
    assert explanation['ml_prediction'] in ['Normal', 'Suspicious']
    assert 'suspicious_probability' in explanation
    assert len(explanation['plain_explanation']) > 0
    print(f"PASS: Explainable AI generated prediction: {explanation['ml_prediction']} (Prob: {explanation['suspicious_probability']}%).")
    print(f"      Top plain explanations: {explanation['plain_explanation']}")

def test_ml_models():
    print("\n--- TEST 4B: ML Models & Baseline Verification ---")
    import joblib
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    rf_path = os.path.join(models_dir, 'random_forest_model.joblib')
    lr_path = os.path.join(models_dir, 'logistic_regression_model.joblib')
    assert os.path.exists(rf_path), "Random Forest model file missing"
    assert os.path.exists(lr_path), "Logistic Regression model file missing"

    rf = joblib.load(rf_path)
    lr = joblib.load(lr_path)

    # Test sample normal vector (all 0s)
    sample_normal = [[0, 0, 0, 0, 0, 0, 0, 0]]
    rf_pred = rf.predict(sample_normal)[0]
    lr_pred = lr.predict(sample_normal)[0]
    assert rf_pred == 0, f"Expected RF normal=0, got {rf_pred}"
    assert lr_pred == 0, f"Expected LR normal=0, got {lr_pred}"

    # Test sample fraud vector (all 1s)
    sample_fraud = [[1, 1, 1, 1, 1, 1, 1, 1]]
    rf_pred_f = rf.predict(sample_fraud)[0]
    lr_pred_f = lr.predict(sample_fraud)[0]
    assert rf_pred_f == 1, f"Expected RF fraud=1, got {rf_pred_f}"
    assert lr_pred_f == 1, f"Expected LR fraud=1, got {lr_pred_f}"
    print("PASS: Both Random Forest and Logistic Regression models loaded and correctly predict sample vectors.")

def test_full_verification_orchestration():
    print("\n--- TEST 5: Full Property Verification Workflow ---")
    
    # 1. Test Clean Property
    res_clean = run_full_property_verification('RS-PROP-0001', trigger_user='TEST_USER')
    assert res_clean is not None
    print(f"RS-PROP-0001: Score={res_clean['risk_score']}, Level={res_clean['risk_level']}, Status={res_clean['verification_status']}")

    # 2. Test Owner Mismatch Property
    res_owner = run_full_property_verification('RS-PROP-0007', trigger_user='TEST_USER')
    assert res_owner['indicators']['owner_mismatch'] is True, "Expected owner mismatch indicator"
    assert res_owner['risk_score'] >= 25
    print(f"RS-PROP-0007: Score={res_owner['risk_score']}, Level={res_owner['risk_level']}, Owner Mismatch Detected: {res_owner['indicators']['owner_mismatch']}")

    # 3. Test Survey Mismatch Property
    res_survey = run_full_property_verification('RS-PROP-0015', trigger_user='TEST_USER')
    assert res_survey['indicators']['survey_mismatch'] is True, "Expected survey mismatch indicator"
    print(f"RS-PROP-0015: Score={res_survey['risk_score']}, Level={res_survey['risk_level']}, Survey Mismatch Detected: {res_survey['indicators']['survey_mismatch']}")

    # 4. Test Hash Mismatch Property
    res_hash = run_full_property_verification('RS-PROP-0031', trigger_user='TEST_USER')
    assert res_hash['indicators']['hash_mismatch'] is True, "Expected hash mismatch indicator"
    print(f"RS-PROP-0031: Score={res_hash['risk_score']}, Level={res_hash['risk_level']}, Hash Mismatch Detected: {res_hash['indicators']['hash_mismatch']}")

    # 5. Test High-Risk Multi-Indicator Property
    res_high = run_full_property_verification('RS-PROP-0058', trigger_user='TEST_USER')
    assert res_high['risk_score'] >= 60, f"Expected high risk score >= 60, got {res_high['risk_score']}"
    assert res_high['risk_level'] in ['High Risk', 'Critical Risk'], f"Expected High or Critical Risk, got {res_high['risk_level']}"
    print(f"RS-PROP-0058: Score={res_high['risk_score']}, Level={res_high['risk_level']}")

    print("PASS: Full verification orchestration validated across all benchmark test cases.")

if __name__ == '__main__':
    try:
        test_hash_tampering()
        test_duplicate_detection()
        test_risk_scoring()
        test_explainable_ai()
        test_ml_models()
        test_full_verification_orchestration()
        print("\n=======================================================")
        print("ALL 6 BACKEND VERIFICATION SUITES PASSED SUCCESSFULLY!")
        print("=======================================================")
    except Exception as e:
        print("\nTEST FAILED:", e)
        import traceback
        traceback.print_exc()
        sys.exit(1)
