"""
REALSAFE Duplicate Property Detection Service
Detects potential duplicate property registrations based on matching Survey Numbers,
Villages/Taluks, and Land Area overlaps across distinct Property IDs or owners.
"""

from models.database import get_db_connection

def find_duplicates_for_property(property_id):
    """
    Checks if the specified property has identical or suspiciously overlapping
    geographic and legal attributes with other registered properties.
    
    Returns:
        dict: {
            'is_duplicate': bool,
            'duplicate_count': int,
            'matches': list of matching property summaries,
            'message': str
        }
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get target property details
    cursor.execute("""
        SELECT property_id, owner_name, survey_number, land_area, district, taluk, village, location
        FROM properties
        WHERE property_id = ?
    """, (property_id,))
    target = cursor.fetchone()

    if not target:
        conn.close()
        return {'is_duplicate': False, 'duplicate_count': 0, 'matches': [], 'message': 'Property not found.'}

    # Query for potential duplicates:
    # 1. Exact survey number + village/taluk match under different Property ID
    # 2. Or exact survey number + land area match
    cursor.execute("""
        SELECT property_id, owner_name, survey_number, land_area, district, taluk, village, location, registration_date
        FROM properties
        WHERE property_id != ?
          AND (
            (TRIM(LOWER(survey_number)) = TRIM(LOWER(?)) AND TRIM(LOWER(taluk)) = TRIM(LOWER(?)))
            OR
            (TRIM(LOWER(survey_number)) = TRIM(LOWER(?)) AND ABS(land_area - ?) <= (? * 0.05))
          )
    """, (
        property_id,
        target['survey_number'], target['taluk'],
        target['survey_number'], target['land_area'], target['land_area']
    ))

    matches = [dict(row) for row in cursor.fetchall()]
    conn.close()

    if matches:
        matched_ids = [m['property_id'] for m in matches]
        msg = f"Review Required — Potential Duplicate Property: Property {property_id} shares matching Survey Number '{target['survey_number']}' and overlapping location/area parameters with {', '.join(matched_ids)}."
        return {
            'is_duplicate': True,
            'duplicate_count': len(matches),
            'matches': matches,
            'message': msg
        }

    return {
        'is_duplicate': False,
        'duplicate_count': 0,
        'matches': [],
        'message': 'No duplicate properties detected.'
    }

def scan_all_duplicates():
    """
    Scans the entire database for potential duplicate clusters.
    Returns a dictionary mapping property_id to duplicate findings.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT property_id FROM properties")
    all_props = [row['property_id'] for row in cursor.fetchall()]
    conn.close()

    results = {}
    for pid in all_props:
        dup = find_duplicates_for_property(pid)
        if dup['is_duplicate']:
            results[pid] = dup
    return results
