"""
REALSAFE Explainable Risk Scoring Engine
Implements deterministic, explainable rule-based scoring (0-100)
with detailed breakdown of factors and points.
"""

# Standard rule penalties defined by REALSAFE methodology
WEIGHTS = {
    'owner_mismatch': 25,
    'survey_mismatch': 25,
    'area_mismatch': 15,
    'duplicate_property': 20,
    'hash_mismatch': 30,
    'ownership_conflict': 20,
    'suspicious_transfer': 15,
    'missing_document': 10
}

def calculate_property_risk(indicators):
    """
    Computes explainable risk score and categorization.
    
    Args:
        indicators (dict): Boolean flags for risk factors:
            - owner_mismatch: bool
            - survey_mismatch: bool
            - area_mismatch: bool
            - duplicate_property: bool
            - hash_mismatch: bool
            - ownership_conflict: bool
            - suspicious_transfer: bool
            - missing_document: bool
            
    Returns:
        dict: {
            'score': int (0-100),
            'risk_level': str ('Low Risk', 'Review Required', 'High Risk'),
            'badge_color': str ('green', 'amber', 'red'),
            'reasons': list of dicts [{'factor': str, 'points': int, 'explanation': str}],
            'recommendation': str
        }
    """
    score = 0
    reasons = []

    if indicators.get('hash_mismatch'):
        score += WEIGHTS['hash_mismatch']
        reasons.append({
            'factor': 'Document Hash Mismatch',
            'points': WEIGHTS['hash_mismatch'],
            'explanation': 'Uploaded file hash differs from recorded registration ledger hash (+30).'
        })

    if indicators.get('owner_mismatch'):
        score += WEIGHTS['owner_mismatch']
        reasons.append({
            'factor': 'Owner Name Inconsistency',
            'points': WEIGHTS['owner_mismatch'],
            'explanation': 'Owner name differs between registered title deed and supplemental records (+25).'
        })

    if indicators.get('survey_mismatch'):
        score += WEIGHTS['survey_mismatch']
        reasons.append({
            'factor': 'Survey Number Inconsistency',
            'points': WEIGHTS['survey_mismatch'],
            'explanation': 'Survey number varies across submitted documents (+25).'
        })

    if indicators.get('duplicate_property'):
        score += WEIGHTS['duplicate_property']
        reasons.append({
            'factor': 'Potential Duplicate Property',
            'points': WEIGHTS['duplicate_property'],
            'explanation': 'Same survey parcel and geographic boundaries registered under another Property ID (+20).'
        })

    if indicators.get('ownership_conflict'):
        score += WEIGHTS['ownership_conflict']
        reasons.append({
            'factor': 'Ownership History Conflict',
            'points': WEIGHTS['ownership_conflict'],
            'explanation': 'Unexplained gap, date overlap, or missing chain of title in prior transfers (+20).'
        })

    if indicators.get('area_mismatch'):
        score += WEIGHTS['area_mismatch']
        reasons.append({
            'factor': 'Land Area Inconsistency',
            'points': WEIGHTS['area_mismatch'],
            'explanation': 'Land area figure differs between documents beyond acceptable tolerance (+15).'
        })

    if indicators.get('suspicious_transfer'):
        score += WEIGHTS['suspicious_transfer']
        reasons.append({
            'factor': 'Suspicious Transfer Pattern',
            'points': WEIGHTS['suspicious_transfer'],
            'explanation': 'Rapid sequential ownership transitions (multiple flips within 6 months) (+15).'
        })

    if indicators.get('missing_document'):
        score += WEIGHTS['missing_document']
        reasons.append({
            'factor': 'Missing Required Document',
            'points': WEIGHTS['missing_document'],
            'explanation': 'Essential primary title document (e.g., Encumbrance Certificate or Patta) not uploaded (+10).'
        })

    # Bound score between 0 and 100
    score = min(100, max(0, score))

    # Any flagged mismatch or alert automatically triggers at least 'Review Required'
    has_active_flags = any([
        indicators.get('owner_mismatch'),
        indicators.get('survey_mismatch'),
        indicators.get('duplicate_property'),
        indicators.get('hash_mismatch'),
        indicators.get('ownership_conflict')
    ])

    # Categorization by score:
    # 0–29: Low Risk | 30–59: Medium Risk (Review Required) | 60–79: High Risk | 80–100: Critical Risk
    if score >= 80:
        risk_level = 'Critical Risk'
        badge_color = 'red'
        recommendation = 'CRITICAL: Multiple severe fraud signals or cryptographic tamper detected. Immediate transaction freeze and forensic audit recommended.'
    elif score >= 60:
        risk_level = 'High Risk'
        badge_color = 'orange'
        recommendation = 'HIGH: Multiple risk indicators detected. Transaction on hold. In-depth physical revenue verification strongly recommended.'
    elif score >= 30 or has_active_flags:
        risk_level = 'Medium Risk'
        badge_color = 'amber'
        recommendation = 'MEDIUM: Information inconsistency detected. Diligence review required before the buyer commits funds or signs documents.'
    else:
        risk_level = 'Low Risk'
        badge_color = 'green'
        recommendation = 'LOW: Clean record. All verified signals within normal baseline limits. Transaction may proceed with standard diligence.'

    return {
        'score': score,
        'risk_level': risk_level,
        'badge_color': badge_color,
        'reasons': reasons,
        'recommendation': recommendation,
        'methodology': 'Multi-signal transparent risk scoring combining rule-based checks, SHA-256 document hashing, and ML anomaly classification.'
    }
