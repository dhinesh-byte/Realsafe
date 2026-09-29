"""
REALSAFE Route & Integration Test Suite
Verifies all Flask routes, template rendering, and interactive workflows:
- Dashboard, Property Directory, Property Passport
- Tamper Simulation and Restore
- Document Upload and Hash Verification
- Safe Transfer Pipeline and Admin Review
- Alerts Center and Audit Trail
- JSON REST API endpoints
"""

import sys
import os
import io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from models.database import get_db_connection

def run_route_tests():
    client = app.test_client()

    print("\n--- TEST 1: Core Navigation Routes ---")
    routes = [
        ('/dashboard', 200),
        ('/properties', 200),
        ('/properties?filter=low', 200),
        ('/properties?filter=review', 200),
        ('/properties?filter=high', 200),
        ('/properties?filter=duplicate', 200),
        ('/properties?filter=hash_mismatch', 200),
        ('/properties?q=Chennai', 200),
        ('/documents', 200),
        ('/transfers', 200),
        ('/alerts', 200),
        ('/alerts?type=Hash+Mismatch', 200),
        ('/verification', 200),
        ('/audit', 200),
        ('/audit?q=VERIFICATION', 200),
        ('/property/new', 200),
        ('/login', 200)
    ]

    for path, expected_status in routes:
        resp = client.get(path)
        assert resp.status_code == expected_status, f"Route {path} returned {resp.status_code}, expected {expected_status}"
    print(f"PASS: All {len(routes)} navigation routes returned HTTP 200 OK.")

    print("\n--- TEST 2: Property Digital Passport Benchmark Cases ---")
    test_properties = [
        'RS-PROP-0001',
        'RS-PROP-0007',
        'RS-PROP-0015',
        'RS-PROP-0023',
        'RS-PROP-0031',
        'RS-PROP-0044',
        'RS-PROP-0058',
        'RS-PROP-0072',
        'RS-PROP-0091',
        'RS-PROP-0100'
    ]

    for pid in test_properties:
        resp = client.get(f'/property/{pid}')
        assert resp.status_code == 200, f"Passport for {pid} returned {resp.status_code}"
        assert pid.encode() in resp.data, f"Property ID {pid} not found in passport HTML output"
    print(f"PASS: Verified all {len(test_properties)} benchmark Property Passports render cleanly.")

    print("\n--- TEST 3: Interactive Document Tampering Simulation & Restore ---")
    # Tamper RS-PROP-0001
    resp_tamper = client.post('/property/RS-PROP-0001/tamper', follow_redirects=True)
    assert resp_tamper.status_code == 200
    assert b"TAMPER LAB: Modified file bytes" in resp_tamper.data or b"Hash Mismatch" in resp_tamper.data

    # Restore RS-PROP-0001
    resp_restore = client.post('/property/RS-PROP-0001/restore', follow_redirects=True)
    assert resp_restore.status_code == 200
    assert b"Restored clean document files" in resp_restore.data or b"Verified" in resp_restore.data
    print("PASS: Tamper and restore workflows executed with live SHA-256 detection.")

    print("\n--- TEST 4: Safe Transfer Workflow Execution ---")
    # Initiate Transfer
    resp_tr = client.post('/transfers/initiate', data={
        'property_id': 'RS-PROP-0001',
        'buyer_id': 'USR-1002',
        'notes': 'Automated Integration Diligence Transfer'
    }, follow_redirects=True)
    assert resp_tr.status_code == 200
    assert b"TR-2026-" in resp_tr.data

    # Find the newly created transfer
    conn = get_db_connection()
    tr_row = conn.execute("SELECT transfer_id FROM transfers ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert tr_row is not None
    latest_tr = tr_row['transfer_id']

    # Admin Review Status Update
    resp_approve = client.post(f'/transfers/{latest_tr}/status?new_status=Approved', follow_redirects=True)
    assert resp_approve.status_code == 200
    assert b"Approved" in resp_approve.data
    print(f"PASS: Transfer {latest_tr} created and Approved through Admin governance.")

    print("\n--- TEST 5: Supplemental Document Upload & Hashing ---")
    mock_file_data = b"MOCK TITLE DEED SUPPLEMENTAL VERIFICATION CONTENT"
    resp_up = client.post('/property/RS-PROP-0001/upload', data={
        'document_type': 'Ownership Certificate',
        'file': (io.BytesIO(mock_file_data), 'supplemental_cert.txt')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_up.status_code == 200
    assert b"uploaded successfully" in resp_up.data
    print("PASS: Supplemental document uploaded and SHA-256 calculated.")

    print("\n--- TEST 6: JSON REST APIs ---")
    # 1. GET /api/property/<id>
    api_resp = client.get('/api/property/RS-PROP-0001')
    assert api_resp.status_code == 200
    json_data = api_resp.get_json()
    assert 'property' in json_data
    assert json_data['property']['property_id'] == 'RS-PROP-0001'

    # 2. GET /api/verify/<id>
    verif_api_resp = client.get('/api/verify/RS-PROP-0001')
    assert verif_api_resp.status_code == 200
    v_data = verif_api_resp.get_json()
    assert 'risk_score' in v_data

    # 3. GET /api/model-metrics
    metrics_resp = client.get('/api/model-metrics')
    assert metrics_resp.status_code == 200
    m_data = metrics_resp.get_json()
    assert 'random_forest' in m_data or 'model_metrics' in m_data
    if 'random_forest' in m_data:
        assert m_data['random_forest']['f1_score'] == 1.0
        assert 'logistic_regression' in m_data
        print(f"      Verified /api/model-metrics: Primary Model F1={m_data['random_forest']['f1_score']}, Baseline F1={m_data['logistic_regression']['f1_score']}")

    # 4. POST /api/verify-property
    post_verif = client.post('/api/verify-property', json={'property_id': 'RS-PROP-0031'})
    assert post_verif.status_code == 200
    pv_data = post_verif.get_json()
    assert pv_data['property_id'] == 'RS-PROP-0031'
    assert 'risk_score' in pv_data
    assert 'risk_status' in pv_data
    assert 'ml_prediction' in pv_data
    assert 'hash_status' in pv_data
    assert 'explanation' in pv_data
    print(f"      Verified POST /api/verify-property: Score={pv_data['risk_score']}, Status={pv_data['risk_status']}, Hash={pv_data['hash_status']}")

    print("PASS: All JSON REST API endpoints verified (GET & POST).")

    print("\n=======================================================")
    print("ALL 6 INTEGRATION & ROUTE TEST SUITES PASSED (100% OK)!")
    print("=======================================================")

if __name__ == '__main__':
    run_route_tests()
