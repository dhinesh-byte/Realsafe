"""
REALSAFE Cross-Document Mismatch Detection Service
Detects discrepancies across property documents and registration records.
Flags issues objectively as "Review Required — information inconsistency detected"
without asserting legal fraud.
"""

from difflib import SequenceMatcher

def normalize_str(s):
    if not s:
        return ""
    return " ".join(str(s).strip().lower().split())

def string_similarity(a, b):
    """Calculates text similarity ratio between two strings (0.0 to 1.0)."""
    norm_a = normalize_str(a)
    norm_b = normalize_str(b)
    if not norm_a and not norm_b:
        return 1.0
    if not norm_a or not norm_b:
        return 0.0
    return SequenceMatcher(None, norm_a, norm_b).ratio()

def detect_mismatches(property_record, documents_data_list, ownership_history=None):
    """
    Performs cross-document and document-to-property comparison.
    
    Args:
        property_record (dict-like): Master property table record.
        documents_data_list (list of dict-like): Extracted document_data records.
        ownership_history (list of dict-like, optional): Past ownership records.
        
    Returns:
        dict: {
            'has_mismatch': bool,
            'mismatch_count': int,
            'details': list of dicts describing each mismatch,
            'fields_flagged': set of field names
        }
    """
    mismatches = []
    fields_flagged = set()

    if not documents_data_list:
        return {
            'has_mismatch': False,
            'mismatch_count': 0,
            'details': [],
            'fields_flagged': fields_flagged
        }

    prop_owner = property_record.get('owner_name', '')
    prop_survey = property_record.get('survey_number', '')
    prop_area = property_record.get('land_area', 0.0)
    prop_loc = property_record.get('location', '')
    prop_reg_date = property_record.get('registration_date', '')
    prop_prev_owner = property_record.get('previous_owner', '')

    # 1. Compare each document data against property master record
    for doc in documents_data_list:
        doc_id = doc.get('document_id', 'Unknown Doc')
        doc_type = doc.get('document_type', 'Document')
        
        # Owner Name Check
        doc_owner = doc.get('owner_name')
        if doc_owner and normalize_str(doc_owner) != normalize_str(prop_owner):
            sim = string_similarity(doc_owner, prop_owner)
            mismatches.append({
                'type': 'Owner Name Mismatch',
                'field': 'owner_name',
                'severity': 'High',
                'document_id': doc_id,
                'document_type': doc_type,
                'master_value': prop_owner,
                'document_value': doc_owner,
                'similarity': round(sim, 2),
                'message': f"Review Required — information inconsistency detected in Owner Name: Property record states '{prop_owner}' but {doc_type} ({doc_id}) lists '{doc_owner}'."
            })
            fields_flagged.add('owner_name')

        # Survey Number Check
        doc_survey = doc.get('survey_number')
        if doc_survey and normalize_str(doc_survey) != normalize_str(prop_survey):
            mismatches.append({
                'type': 'Survey Number Mismatch',
                'field': 'survey_number',
                'severity': 'High',
                'document_id': doc_id,
                'document_type': doc_type,
                'master_value': prop_survey,
                'document_value': doc_survey,
                'message': f"Review Required — information inconsistency detected in Survey Number: Master record lists '{prop_survey}' while {doc_type} ({doc_id}) shows '{doc_survey}'."
            })
            fields_flagged.add('survey_number')

        # Land Area Check (Tolerance of 1% to account for rounding)
        doc_area = doc.get('land_area')
        if doc_area is not None and prop_area:
            try:
                area_diff = abs(float(doc_area) - float(prop_area))
                pct_diff = area_diff / float(prop_area)
                if pct_diff > 0.01:
                    mismatches.append({
                        'type': 'Land Area Mismatch',
                        'field': 'land_area',
                        'severity': 'Medium',
                        'document_id': doc_id,
                        'document_type': doc_type,
                        'master_value': f"{prop_area} sq.ft",
                        'document_value': f"{doc_area} sq.ft",
                        'variance': f"{round(pct_diff * 100, 1)}%",
                        'message': f"Review Required — information inconsistency detected in Land Area: Master record states {prop_area} sq.ft, but {doc_type} ({doc_id}) states {doc_area} sq.ft (variance of {round(pct_diff * 100, 1)}%)."
                    })
                    fields_flagged.add('land_area')
            except (ValueError, TypeError):
                pass

        # Location / Village / Taluk Check
        doc_loc = doc.get('location')
        if doc_loc and normalize_str(doc_loc) != normalize_str(prop_loc):
            sim_loc = string_similarity(doc_loc, prop_loc)
            if sim_loc < 0.75:
                mismatches.append({
                    'type': 'Location Mismatch',
                    'field': 'location',
                    'severity': 'Medium',
                    'document_id': doc_id,
                    'document_type': doc_type,
                    'master_value': prop_loc,
                    'document_value': doc_loc,
                    'message': f"Review Required — information inconsistency detected in Location: Master record lists '{prop_loc}', whereas {doc_type} specifies '{doc_loc}'."
                })
                fields_flagged.add('location')

    # 2. Cross-document comparison (e.g. Document A vs Document B)
    for i in range(len(documents_data_list)):
        for j in range(i + 1, len(documents_data_list)):
            doc_a = documents_data_list[i]
            doc_b = documents_data_list[j]
            
            # Cross Document Owner Check
            if doc_a.get('owner_name') and doc_b.get('owner_name'):
                if normalize_str(doc_a['owner_name']) != normalize_str(doc_b['owner_name']):
                    if 'owner_name' not in fields_flagged:
                        mismatches.append({
                            'type': 'Cross-Document Owner Inconsistency',
                            'field': 'owner_name',
                            'severity': 'High',
                            'document_id': f"{doc_a.get('document_id')} vs {doc_b.get('document_id')}",
                            'document_type': 'Cross-Check',
                            'master_value': doc_a['owner_name'],
                            'document_value': doc_b['owner_name'],
                            'message': f"Review Required — information inconsistency detected: {doc_a.get('document_type', 'Doc A')} lists '{doc_a['owner_name']}' while {doc_b.get('document_type', 'Doc B')} lists '{doc_b['owner_name']}'."
                        })
                        fields_flagged.add('owner_name')

            # Cross Document Survey Check
            if doc_a.get('survey_number') and doc_b.get('survey_number'):
                if normalize_str(doc_a['survey_number']) != normalize_str(doc_b['survey_number']):
                    if 'survey_number' not in fields_flagged:
                        mismatches.append({
                            'type': 'Cross-Document Survey Inconsistency',
                            'field': 'survey_number',
                            'severity': 'High',
                            'document_id': f"{doc_a.get('document_id')} vs {doc_b.get('document_id')}",
                            'document_type': 'Cross-Check',
                            'master_value': doc_a['survey_number'],
                            'document_value': doc_b['survey_number'],
                            'message': f"Review Required — information inconsistency detected: {doc_a.get('document_type', 'Doc A')} shows '{doc_a['survey_number']}' while {doc_b.get('document_type', 'Doc B')} shows '{doc_b['survey_number']}'."
                        })
                        fields_flagged.add('survey_number')

    # 3. Ownership History Chain of Title Check
    if ownership_history and len(ownership_history) > 1:
        # Check chronological continuity
        sorted_history = sorted(ownership_history, key=lambda x: x.get('start_date', ''))
        for idx in range(len(sorted_history) - 1):
            curr = sorted_history[idx]
            nxt = sorted_history[idx + 1]
            if curr.get('end_date') and nxt.get('start_date'):
                if curr['end_date'] > nxt['start_date']:
                    mismatches.append({
                        'type': 'Ownership Timeline Conflict',
                        'field': 'ownership_history',
                        'severity': 'High',
                        'document_id': 'History Audit',
                        'document_type': 'Chain of Title',
                        'master_value': curr['end_date'],
                        'document_value': nxt['start_date'],
                        'message': f"Review Required — information inconsistency detected in Ownership History: Title transfer date overlap detected between {curr.get('owner_name')} and {nxt.get('owner_name')}."
                    })
                    fields_flagged.add('ownership_history')

    return {
        'has_mismatch': len(mismatches) > 0,
        'mismatch_count': len(mismatches),
        'details': mismatches,
        'fields_flagged': list(fields_flagged)
    }
