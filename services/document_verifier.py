"""
REALSAFE Master Document Verification Orchestrator
Coordinates document hashing, cross-document comparison, duplicate checking,
risk scoring, and audit updates.
"""

import os
from datetime import datetime
from models.database import get_db_connection, log_audit
from services.hash_service import verify_document_hash, safe_upload_path
from services.mismatch_detector import detect_mismatches
from services.duplicate_detector import find_duplicates_for_property
from services.risk_engine import calculate_property_risk
from services.explainable_ai import explain_property_risk

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads')

def run_full_property_verification(property_id, trigger_user="SYSTEM"):
    """
    Executes an end-to-end multi-layer verification check for a property.
    Updates database risk status, alerts, verification records, and audit log.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Fetch Property Master Record
    cursor.execute("SELECT * FROM properties WHERE property_id = ?", (property_id,))
    prop_row = cursor.fetchone()
    if not prop_row:
        conn.close()
        return None
    property_record = dict(prop_row)

    # 2. Fetch Documents and Document Data
    cursor.execute("""
        SELECT d.*, dd.owner_name, dd.survey_number, dd.land_area, dd.location, dd.registration_date as doc_reg_date
        FROM documents d
        LEFT JOIN document_data dd ON d.document_id = dd.document_id
        WHERE d.property_id = ?
    """, (property_id,))
    docs = [dict(r) for r in cursor.fetchall()]

    # 3. Fetch Ownership History
    cursor.execute("SELECT * FROM ownership_history WHERE property_id = ? ORDER BY start_date ASC", (property_id,))
    history = [dict(r) for r in cursor.fetchall()]

    # --- CHECK 1: Document Integrity (SHA-256 Hashes) ---
    hash_mismatch_detected = False
    hash_results = []
    for doc in docs:
        filepath = safe_upload_path(UPLOAD_FOLDER, doc['filename'])
        v_res = verify_document_hash(filepath, doc['sha256_hash']) if filepath else {
            'is_valid': False,
            'current_hash': 'FILE_NOT_FOUND',
            'stored_hash': doc['sha256_hash'],
            'status': 'File Missing',
            'explanation': 'SHA-256 verifies whether the file content has changed relative to the previously recorded hash.'
        }
        hash_results.append({
            'document_id': doc['document_id'],
            'document_type': doc['document_type'],
            'filename': doc['filename'],
            'verification': v_res
        })
        if not v_res['is_valid']:
            hash_mismatch_detected = True
            cursor.execute("UPDATE documents SET verification_status = 'Hash Mismatch' WHERE document_id = ?", (doc['document_id'],))
        else:
            cursor.execute("UPDATE documents SET verification_status = 'Verified' WHERE document_id = ?", (doc['document_id'],))

    # --- CHECK 2: Cross-Document Mismatches ---
    mismatch_report = detect_mismatches(property_record, docs, history)

    # --- CHECK 3: Duplicate Property Detection ---
    duplicate_report = find_duplicates_for_property(property_id)

    # --- CHECK 4: Ownership Conflicts & Rapid Transfers ---
    ownership_conflict_detected = False
    suspicious_transfer_detected = False

    if len(history) > 1:
        for i in range(len(history) - 1):
            h1 = history[i]
            h2 = history[i+1]
            try:
                d1 = datetime.strptime(h1['start_date'], '%Y-%m-%d')
                d2 = datetime.strptime(h2['start_date'], '%Y-%m-%d')
                # Transfer within 180 days (rapid flip)
                if abs((d2 - d1).days) < 180:
                    suspicious_transfer_detected = True
            except Exception:
                pass

        if 'ownership_history' in mismatch_report['fields_flagged']:
            ownership_conflict_detected = True

    # --- CHECK 5: Required Document Completeness ---
    doc_types_present = {d['document_type'] for d in docs}
    required_types = {'Sale Deed', 'Land Record', 'Encumbrance Certificate'}
    missing_document_detected = bool(required_types - doc_types_present)

    # --- ASSEMBLE RISK INDICATORS ---
    indicators = {
        'owner_mismatch': 'owner_name' in mismatch_report['fields_flagged'],
        'survey_mismatch': 'survey_number' in mismatch_report['fields_flagged'],
        'area_mismatch': 'land_area' in mismatch_report['fields_flagged'],
        'duplicate_property': duplicate_report['is_duplicate'],
        'hash_mismatch': hash_mismatch_detected,
        'ownership_conflict': ownership_conflict_detected,
        'suspicious_transfer': suspicious_transfer_detected,
        'missing_document': missing_document_detected
    }

    # Calculate deterministic explainable risk score
    risk_summary = calculate_property_risk(indicators)

    # Calculate Explainable AI & SHAP attribution
    xai_summary = explain_property_risk(indicators)

    # Determine property overall verification status
    if risk_summary['score'] >= 80:
        new_verification_status = 'Critical Risk'
    elif risk_summary['score'] >= 60:
        new_verification_status = 'High Risk'
    elif risk_summary['score'] >= 30:
        new_verification_status = 'Review Required'
    else:
        new_verification_status = 'Verified'

    # Update Property Master Table
    cursor.execute("""
        UPDATE properties
        SET risk_score = ?, risk_level = ?, verification_status = ?
        WHERE property_id = ?
    """, (risk_summary['score'], risk_summary['risk_level'], new_verification_status, property_id))

    # Clear prior active alerts for this property and re-populate
    cursor.execute("DELETE FROM risk_alerts WHERE property_id = ?", (property_id,))

    alerts_to_insert = []
    if hash_mismatch_detected:
        alerts_to_insert.append(('Hash Mismatch', 'SHA-256 document checksum mismatch detected. File bytes differ from registered ledger.', 'High'))
    for mm in mismatch_report['details']:
        alerts_to_insert.append((mm['type'], mm['message'], mm.get('severity', 'Medium')))
    if duplicate_report['is_duplicate']:
        alerts_to_insert.append(('Potential Duplicate Property', duplicate_report['message'], 'High'))
    if suspicious_transfer_detected:
        alerts_to_insert.append(('Rapid Property Transfer', 'Property underwent sequential ownership changes within less than 180 days.', 'Medium'))
    if missing_document_detected:
        missing_names = ", ".join(required_types - doc_types_present)
        alerts_to_insert.append(('Missing Documentation', f'Recommended primary title documentation missing: {missing_names}.', 'Medium'))

    for atype, adesc, asev in alerts_to_insert:
        cursor.execute("""
            INSERT INTO risk_alerts (property_id, alert_type, description, severity, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (property_id, atype, adesc, asev, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    # Record Comprehensive Verification Event (Section 14 Audit Trail)
    hash_status_text = 'Tampering Detected' if hash_mismatch_detected else 'Verified'
    mismatch_status_text = f"{mismatch_report['mismatch_count']} Inconsistencies" if mismatch_report['has_mismatch'] else 'Consistent'

    cursor.execute("""
        INSERT INTO verification_records (
            property_id, verification_type, result, checked_at, details,
            hash_result, mismatch_result, ml_prediction, ml_probability, risk_score, final_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        property_id,
        'Multi-Vector Scan',
        new_verification_status,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        f"Score: {risk_summary['score']}/100 ({risk_summary['risk_level']}). ML: {xai_summary['ml_prediction']} ({xai_summary['suspicious_probability']}%). Alerts: {len(alerts_to_insert)}.",
        hash_status_text,
        mismatch_status_text,
        xai_summary['ml_prediction'],
        float(xai_summary['suspicious_probability']),
        int(risk_summary['score']),
        new_verification_status
    ))

    conn.commit()
    conn.close()

    # Log Audit Trail
    log_audit(
        user_id=trigger_user,
        property_id=property_id,
        action="VERIFICATION_COMPLETED",
        details=f"Calculated Risk Score: {risk_summary['score']} ({risk_summary['risk_level']}). Result: {new_verification_status}."
    )

    return {
        'property_id': property_id,
        'risk_score': risk_summary['score'],
        'risk_level': risk_summary['risk_level'],
        'verification_status': new_verification_status,
        'recommendation': risk_summary['recommendation'],
        'risk_reasons': risk_summary['reasons'],
        'indicators': indicators,
        'hash_results': hash_results,
        'mismatch_report': mismatch_report,
        'duplicate_report': duplicate_report,
        'xai': xai_summary
    }
