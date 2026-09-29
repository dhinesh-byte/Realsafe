"""
REALSAFE Synthetic Dataset & Database Population Generator
Generates 500+ realistic fictional property records and associated document records.
Adheres strictly to synthetic/anonymized data standards using Tamil Nadu revenue divisions.
All data is explicitly marked: "Synthetic development/demo dataset".
Outputs to:
  1. data/property_documents.csv (Document-level relational CSV)
  2. data/synthetic_property_fraud_dataset.csv (Property-level master ML dataset)
  3. database/realsafe.db (SQLite database)
  4. uploads/ (fictional demo document files with SHA-256 hashes)
"""

import os
import random
import hashlib
from datetime import datetime, timedelta
import pandas as pd
from models.database import init_db, get_db_connection
from services.risk_engine import calculate_property_risk
from services.hash_service import compute_sha256_for_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_DIR = os.path.join(BASE_DIR, 'database')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Administrative Reference Tables (Tamil Nadu Revenue Administration style)
DISTRICTS = {
    'Chennai': {
        'taluks': ['Tambaram', 'Alandur', 'Guindy', 'Velachery', 'Mylapore', 'Sholinganallur'],
        'villages': ['Madipakkam', 'Velachery East', 'Pallavaram', 'Keelkattalai', 'Adambakkam', 'Thoraipakkam']
    },
    'Chengalpattu': {
        'taluks': ['Vandalur', 'Chengalpattu', 'Thiruporur', 'Maduranthakam'],
        'villages': ['Guduvancheri', 'Kelambakkam', 'Padur', 'Siruseri', 'Maraimalai Nagar']
    },
    'Kanchipuram': {
        'taluks': ['Sriperumbudur', 'Kanchipuram', 'Walajabad', 'Kundrathur'],
        'villages': ['Irungattukottai', 'Oragadam', 'Mangadu', 'Thandalam', 'Sunguvarchatram']
    },
    'Coimbatore': {
        'taluks': ['Coimbatore South', 'Coimbatore North', 'Pollachi', 'Sulur'],
        'villages': ['Saravanampatti', 'Peelamedu', 'Gandhipuram', 'Kovaipudur', 'Singanallur']
    },
    'Madurai': {
        'taluks': ['Madurai North', 'Madurai South', 'Thirumangalam', 'Melur'],
        'villages': ['Koodal Nagar', 'Anna Nagar', 'Othakadai', 'Thiruparankundram']
    },
    'Tiruchirappalli': {
        'taluks': ['Tiruchirappalli West', 'Srirangam', 'Lalgudi', 'Thiruverumbur'],
        'villages': ['Kallakudi', 'Kattur', 'Srirangam Central', 'Ponmalai']
    }
}

FIRST_NAMES = [
    'Arun', 'Priya', 'Karthik', 'Suresh', 'Deepa', 'Venkatesh', 'Ananya', 'Ramesh',
    'Meenakshi', 'Saravanan', 'Lakshmi', 'Balaji', 'Vijay', 'Divya', 'Sundar', 'Swetha',
    'Ganesh', 'Revathi', 'Manoj', 'Kavitha', 'Rajesh', 'Bhavani', 'Dinesh', 'Nandhini',
    'Aravind', 'Harini', 'Madhavan', 'Poornima', 'Siddharth', 'Gayathri', 'Vignesh', 'Uma'
]

LAST_NAMES = [
    'Kumar', 'Ramesh', 'Sundaram', 'Natarajan', 'Subramanian', 'Krishnan', 'Iyer',
    'Chandran', 'Murugan', 'Pillai', 'Rao', 'Reddy', 'Gopal', 'Vaidyanathan',
    'Swaminathan', 'Thyagarajan', 'Balasubramanian', 'Ganesan', 'Srinivasan'
]

PROPERTY_TYPES = [
    'Residential Plot', 'Independent Villa', 'Commercial Space',
    'Multi-family Apartment', 'Agricultural Land', 'Industrial Warehouse'
]

DOC_TYPES = [
    'Sale Deed',
    'Ownership Certificate',
    'Property Tax Receipt',
    'Encumbrance Certificate',
    'Land Record'
]

# Benchmark demo properties kept label-stable for live walkthroughs
DEMO_PROTECTED_INDICES = {1, 7, 15, 23, 31, 44, 58, 72, 87, 91, 100}
DEMO_PROTECTED_IDS = {f"RS-PROP-{i:04d}" for i in DEMO_PROTECTED_INDICES}

ML_FEATURE_COLUMNS = [
    'owner_mismatch',
    'survey_mismatch',
    'area_mismatch',
    'duplicate_property',
    'hash_mismatch',
    'ownership_history_conflict',
    'suspicious_transfer_pattern',
    'missing_document'
]


def apply_label_noise_to_csv(csv_path, id_col='property_id', seed=42):
    """
    Apply investigator-disagreement noise to an existing ML CSV without wiping SQLite.
    Demo benchmark IDs are left unchanged.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(csv_path)
    df = pd.read_csv(csv_path)
    rng = random.Random(seed)
    if 'fraud_label' not in df.columns or id_col not in df.columns:
        return df
    if 'label_noise_applied' in df.columns and int(df['label_noise_applied'].fillna(0).max()) == 1:
        print(f"Label noise already applied on {csv_path}; skipping.")
        return df
    flipped = 0
    for idx in df.index:
        pid = str(df.at[idx, id_col])
        if pid in DEMO_PROTECTED_IDS:
            continue
        label = int(df.at[idx, 'fraud_label'])
        flag_sum = 0
        for col in ML_FEATURE_COLUMNS:
            if col in df.columns:
                flag_sum += int(df.at[idx, col])
        roll = rng.random()
        new_label = label
        if label == 1 and flag_sum == 1 and roll < 0.18:
            new_label = 0
        elif label == 1 and roll < 0.10:
            new_label = 0
        elif label == 0 and flag_sum >= 1 and roll < 0.12:
            new_label = 1
        elif label == 0 and flag_sum == 0 and roll < 0.04:
            new_label = 1
        if new_label != label:
            df.at[idx, 'fraud_label'] = new_label
            flipped += 1
    df['label_noise_applied'] = 1
    df.to_csv(csv_path, index=False)
    print(f"Applied investigator label noise to {csv_path}: {flipped} labels changed (demo IDs preserved).")
    return df

def generate_name():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"

def create_mock_document_file(filename, title, content_dict, tamper=False):
    """Creates a realistic text-based demo document file and returns its clean SHA-256 ledger hash."""
    filepath = os.path.join(UPLOAD_DIR, filename)
    lines = [
        "===========================================================",
        "          REALSAFE DIGITAL VERIFICATION ARCHIVE",
        f"           DEMO DOCUMENT: {title.upper()}",
        "===========================================================",
        f"Document ID      : {content_dict.get('document_id')}",
        f"Property ID      : {content_dict.get('property_id')}",
        f"Registered Owner : {content_dict.get('owner_name')}",
        f"Survey Number    : {content_dict.get('survey_number')}",
        f"Plot Land Area   : {content_dict.get('land_area')} sq.ft",
        f"Revenue Location : {content_dict.get('location')}",
        f"State / Region   : Tamil Nadu",
        f"Execution Date   : {content_dict.get('registration_date')}",
        f"Issuing Office   : Sub-Registrar Office, Revenue Administration",
        f"Dataset Notice   : Synthetic development/demo dataset. Fictional data.",
        "===========================================================",
    ]
    clean_text = "\n".join(lines)
    clean_sha256 = hashlib.sha256(clean_text.encode('utf-8')).hexdigest()

    file_content = clean_text
    if tamper:
        file_content += "\n<!-- UNAUTHORIZED_BYTE_MODIFICATION_DETECTED -->\n"

    with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
        f.write(file_content)

    return clean_sha256

def generate_full_dataset(num_properties=520):
    """
    Generates >= 500 realistic synthetic properties with relational documents,
    audit records, and distinct fraud vectors.
    """
    print(f"Generating synthetic development/demo dataset of {num_properties} properties...")
    random.seed(42)

    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Clear existing tables safely
    cursor.execute("DELETE FROM audit_logs")
    cursor.execute("DELETE FROM verification_records")
    cursor.execute("DELETE FROM risk_alerts")
    cursor.execute("DELETE FROM transfers")
    cursor.execute("DELETE FROM ownership_history")
    cursor.execute("DELETE FROM document_data")
    cursor.execute("DELETE FROM documents")
    cursor.execute("DELETE FROM properties")
    cursor.execute("DELETE FROM users")

    # 1. Insert Demo Personas and Users
    demo_users = [
        ('USR-1001', 'Arun Kumar', 'seller', 'Verified', 'seller_hash', 'arun.kumar@demo.realsafe.internal'),
        ('USR-1002', 'Priya Ramesh', 'buyer', 'Verified', 'buyer_hash', 'priya.ramesh@demo.realsafe.internal'),
        ('USR-1000', 'Vikram Sundar (Admin)', 'admin', 'Verified', 'admin_hash', 'admin@realsafe.internal'),
        ('USR-1003', 'Karthik Raja', 'seller', 'Verified', 'seller_hash', 'karthik.raja@demo.realsafe.internal'),
        ('USR-1004', 'Deepa Murugan', 'buyer', 'Verified', 'buyer_hash', 'deepa.murugan@demo.realsafe.internal'),
        ('USR-1005', 'Suresh Krishnan', 'seller', 'Verified', 'seller_hash', 'suresh.k@demo.realsafe.internal'),
        ('USR-1006', 'Meenakshi Iyer', 'buyer', 'Verified', 'buyer_hash', 'meena.iyer@demo.realsafe.internal'),
    ]
    # Add additional synthetic users for broader variety
    for u_idx in range(7, 60):
        u_role = 'seller' if u_idx % 2 == 0 else 'buyer'
        u_name = generate_name()
        demo_users.append((
            f"USR-{1000 + u_idx}",
            u_name,
            u_role,
            'Verified',
            'demo_hash',
            f"{u_name.lower().replace(' ', '.')}@demo.realsafe.internal"
        ))

    for u in demo_users:
        cursor.execute("""
            INSERT INTO users (verified_user_id, name, role, verification_status, password_hash, email)
            VALUES (?, ?, ?, ?, ?, ?)
        """, u)

    seller_ids = [u[0] for u in demo_users if u[2] == 'seller']
    buyer_ids = [u[0] for u in demo_users if u[2] == 'buyer']

    document_csv_rows = []
    property_ml_rows = []

    for i in range(1, num_properties + 1):
        prop_num_str = f"{i:04d}"
        prop_id = f"RS-PROP-{prop_num_str}"
        owner_id = seller_ids[(i - 1) % len(seller_ids)]
        seller_id = owner_id
        buyer_id = buyer_ids[(i - 1) % len(buyer_ids)]
        owner_name = generate_name()

        # Location picking
        dist = random.choice(list(DISTRICTS.keys()))
        taluk = random.choice(DISTRICTS[dist]['taluks'])
        village = random.choice(DISTRICTS[dist]['villages'])
        location_str = f"{village}, {taluk}, {dist}"
        state_str = "Tamil Nadu"

        survey_no = f"SUR-{random.randint(100, 999)}/{random.randint(1, 9)}{random.choice(['A', 'B', 'C', '1', '2'])}"
        land_area = float(random.choice([1200, 1500, 1800, 2400, 3000, 3600, 4800, 5400, 9600]))
        area_unit = 'sq.ft'
        prop_type = random.choice(PROPERTY_TYPES)

        reg_year = random.randint(2018, 2024)
        reg_month = random.randint(1, 12)
        reg_day = random.randint(1, 28)
        reg_date = f"{reg_year}-{reg_month:02d}-{reg_day:02d}"

        prev_owner = generate_name()
        transfer_date = f"{reg_year - random.randint(2, 6)}-04-15"
        transfer_count = random.randint(1, 4)

        # Baseline flags
        is_owner_mismatch = False
        is_survey_mismatch = False
        is_area_mismatch = False
        is_duplicate = False
        is_tampered_hash = False
        is_ownership_conflict = False
        is_suspicious_transfer = False
        is_missing_doc = False

        # --- PRESERVE SPECIFIED BENCHMARK CASES ---
        if i == 1:
            # CASE 1: Clean / Normal baseline reference
            owner_name = "Arun Kumar"
            owner_id = "USR-1001"
            seller_id = "USR-1001"
            buyer_id = "USR-1002"
            survey_no = "SUR-458/2A"
            land_area = 2400.0
            dist = "Chennai"
            taluk = "Tambaram"
            village = "Madipakkam"
            location_str = f"{village}, {taluk}, {dist}"
            prop_type = "Residential Plot"
            reg_date = "2022-06-14"
            prev_owner = "Sundar Raman"
            transfer_date = "2016-03-20"
            transfer_count = 2

        elif i == 7:
            # Benchmark 7: Owner Mismatch case
            owner_name = "Arun Kumar"
            is_owner_mismatch = True

        elif i == 15:
            # Benchmark 15: Survey Number Mismatch case
            survey_no = "SUR-458/2A"
            is_survey_mismatch = True

        elif i == 23:
            # Benchmark 23: Potential duplicate case (Matches with Property 0087)
            survey_no = "SUR-882/4C"
            dist = "Chengalpattu"
            taluk = "Vandalur"
            village = "Guduvancheri"
            location_str = f"{village}, {taluk}, {dist}"
            land_area = 2400.0
            is_duplicate = True

        elif i == 31:
            # CASE 2: Document hash tampering simulation
            is_tampered_hash = True

        elif i == 44:
            # Benchmark 44: Ownership history conflict / timeline gap
            is_ownership_conflict = True
            transfer_count = 4

        elif i == 58:
            # Benchmark 58: Multi-Risk Vector
            is_owner_mismatch = True
            is_survey_mismatch = True
            is_duplicate = True
            is_tampered_hash = True
            is_ownership_conflict = True
            transfer_count = 5

        elif i == 72:
            # Benchmark 72: Incomplete documentation / missing primary deeds
            is_missing_doc = True

        elif i == 87:
            # Benchmark 87: Duplicate partner of Property 0023
            survey_no = "SUR-882/4C"
            dist = "Chengalpattu"
            taluk = "Vandalur"
            village = "Guduvancheri"
            location_str = f"{village}, {taluk}, {dist}"
            land_area = 2400.0
            is_duplicate = True

        elif i == 91:
            # Benchmark 91: Rapid sequential transfers / suspicious velocity
            is_suspicious_transfer = True
            transfer_count = 4

        elif i == 100:
            # Benchmark 100: Clean verified reference
            owner_name = "Priya Ramesh"
            owner_id = "USR-1002"
            seller_id = "USR-1002"
            buyer_id = "USR-1004"
            survey_no = "SUR-102/3B"
            land_area = 1800.0
            dist = "Chennai"
            taluk = "Alandur"
            village = "Madipakkam"
            location_str = f"{village}, {taluk}, {dist}"
            reg_date = "2023-01-10"
            transfer_count = 1

        else:
            # Realistic synthetic variations for remaining records
            # Create a realistic 65% clean / 35% suspicious distribution
            rand_profile = random.random()
            if rand_profile < 0.35:
                # Suspicious profile: combinations of various fraud signals
                sub_pattern = random.randint(1, 8)
                if sub_pattern == 1:
                    is_owner_mismatch = True
                elif sub_pattern == 2:
                    is_survey_mismatch = True
                elif sub_pattern == 3:
                    is_area_mismatch = True
                elif sub_pattern == 4:
                    is_ownership_conflict = True
                    transfer_count = random.randint(3, 6)
                elif sub_pattern == 5:
                    is_suspicious_transfer = True
                    transfer_count = random.randint(3, 5)
                elif sub_pattern == 6:
                    is_missing_doc = True
                elif sub_pattern == 7:
                    # Multi-flag combination (e.g. owner + survey mismatch)
                    is_owner_mismatch = True
                    is_survey_mismatch = True
                elif sub_pattern == 8:
                    # Multi-flag combination (e.g. area mismatch + missing doc)
                    is_area_mismatch = True
                    is_missing_doc = True

                # Occasional secondary flag for realistic depth
                if random.random() < 0.15:
                    is_suspicious_transfer = True
                if random.random() < 0.08:
                    is_tampered_hash = True
                if random.random() < 0.08:
                    is_duplicate = True

        # Binary fraud indicators dictionary
        indicators = {
            'owner_mismatch': is_owner_mismatch,
            'survey_mismatch': is_survey_mismatch,
            'area_mismatch': is_area_mismatch,
            'duplicate_property': is_duplicate,
            'hash_mismatch': is_tampered_hash,
            'ownership_conflict': is_ownership_conflict,
            'suspicious_transfer': is_suspicious_transfer,
            'missing_document': is_missing_doc
        }

        # Investigator-style label (not a perfect function of the 8 ML features).
        # Major signals usually indicate fraud-like cases, but clerical mismatches
        # and incomplete investigations produce label disagreement — required for
        # honest train/test evaluation instead of 100% separable accuracy.
        has_major_flag = is_owner_mismatch or is_survey_mismatch or is_duplicate or is_tampered_hash or is_ownership_conflict
        total_flags = sum(1 for f in indicators.values() if f)
        fraud_label = 1 if (has_major_flag or total_flags >= 2 or (is_suspicious_transfer and is_area_mismatch)) else 0
        if i not in DEMO_PROTECTED_INDICES:
            roll = random.random()
            if fraud_label == 1 and total_flags == 1 and roll < 0.18:
                fraud_label = 0  # isolated signal later treated as clerical
            elif fraud_label == 1 and roll < 0.10:
                fraud_label = 0  # investigation closed without confirmed fraud
            elif fraud_label == 0 and total_flags >= 1 and roll < 0.12:
                fraud_label = 1  # weak signals later confirmed
            elif fraud_label == 0 and total_flags == 0 and roll < 0.04:
                fraud_label = 1  # hidden issue not captured by current detectors

        # Calculate deterministic risk score
        risk_res = calculate_property_risk(indicators)
        risk_score = risk_res['score']
        risk_level = risk_res['risk_level']

        # Ensure benchmark clean properties stay 0 risk
        if i == 1:
            risk_score = 0
            risk_level = 'Low Risk'
            fraud_label = 0
        elif i == 100:
            risk_score = 0
            risk_level = 'Low Risk'
            fraud_label = 0

        verif_status = 'Verified' if risk_score < 30 else ('Review Required' if risk_score < 60 else 'High Risk')

        # Insert Property into SQLite
        cursor.execute("""
            INSERT INTO properties (
                property_id, owner_id, owner_name, survey_number, land_area, area_unit,
                property_type, district, taluk, village, location, registration_date,
                ownership_status, verification_status, risk_score, risk_level,
                previous_owner, transfer_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            prop_id, owner_id, owner_name, survey_no, land_area, area_unit,
            prop_type, dist, taluk, village, location_str, reg_date,
            'Active', verif_status, risk_score, risk_level,
            prev_owner, transfer_date
        ))

        # Insert Ownership History
        cursor.execute("""
            INSERT INTO ownership_history (property_id, owner_name, start_date, end_date, transfer_reference, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            prop_id, prev_owner,
            f"{int(reg_date[:4]) - 6}-02-10",
            reg_date if not is_ownership_conflict else f"{int(reg_date[:4]) + 1}-01-01",
            f"DOC-REG-{random.randint(1000, 9999)}",
            "Transferred via Registered Conveyance Deed"
        ))

        if is_suspicious_transfer:
            mid_owner = generate_name()
            cursor.execute("""
                INSERT INTO ownership_history (property_id, owner_name, start_date, end_date, transfer_reference, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                prop_id, mid_owner,
                reg_date,
                (datetime.strptime(reg_date, '%Y-%m-%d') + timedelta(days=45)).strftime('%Y-%m-%d'),
                f"RAPID-TR-{random.randint(100, 999)}",
                "High-frequency quick turnaround transfer"
            ))

        cursor.execute("""
            INSERT INTO ownership_history (property_id, owner_name, start_date, end_date, transfer_reference, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            prop_id, owner_name,
            reg_date,
            None,
            f"DEED-{random.randint(10000, 99999)}",
            "Current Legal Record Holder"
        ))

        # Documents to generate
        docs_to_create = ['Sale Deed', 'Land Record', 'Encumbrance Certificate']
        if is_missing_doc:
            docs_to_create = ['Sale Deed']
        elif random.random() < 0.4:
            docs_to_create.append('Property Tax Receipt')

        primary_doc_hash = ""

        for d_idx, dtype in enumerate(docs_to_create):
            doc_id = f"RS-DOC-{prop_num_str}-{d_idx + 1}"
            filename = f"{prop_id}_{dtype.replace(' ', '_').lower()}.txt"

            doc_owner = owner_name
            doc_survey = survey_no
            doc_area = land_area
            doc_loc = location_str

            # Apply simulated mismatches
            if is_owner_mismatch and dtype == 'Land Record':
                doc_owner = "Arjun Kumar" if owner_name == "Arun Kumar" else f"{owner_name.split()[0]}a {owner_name.split()[-1]}"
            if is_survey_mismatch and dtype == 'Land Record':
                doc_survey = f"{survey_no[:-1]}B" if survey_no.endswith('A') else f"{survey_no}/ALT"
            if is_area_mismatch and dtype in ['Property Tax Receipt', 'Land Record']:
                doc_area = land_area + 350.0

            content_dict = {
                'document_id': doc_id,
                'property_id': prop_id,
                'owner_name': doc_owner,
                'survey_number': doc_survey,
                'land_area': doc_area,
                'location': doc_loc,
                'registration_date': reg_date
            }

            is_this_doc_tampered = bool(is_tampered_hash and dtype == 'Sale Deed')
            sha_hash = create_mock_document_file(filename, dtype, content_dict, tamper=is_this_doc_tampered)
            if dtype == 'Sale Deed':
                primary_doc_hash = sha_hash
            doc_verif = 'Hash Mismatch' if is_this_doc_tampered else 'Verified'

            cursor.execute("""
                INSERT INTO documents (document_id, property_id, document_type, filename, sha256_hash, upload_date, verification_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                doc_id, prop_id, dtype, filename, sha_hash, reg_date, doc_verif
            ))

            cursor.execute("""
                INSERT INTO document_data (document_id, owner_name, survey_number, land_area, location, registration_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                doc_id, doc_owner, doc_survey, doc_area, doc_loc, reg_date
            ))

            document_csv_rows.append({
                'property_id': prop_id,
                'owner_id': owner_id,
                'owner_name': owner_name,
                'seller_id': seller_id,
                'buyer_id': buyer_id,
                'survey_number': survey_no,
                'land_area': land_area,
                'location': location_str,
                'district': dist,
                'state': state_str,
                'document_type': dtype,
                'document_id': doc_id,
                'registration_date': reg_date,
                'previous_owner': prev_owner,
                'ownership_transfer_count': transfer_count,
                'document_hash': sha_hash,
                'document_status': doc_verif,
                'owner_match': 0 if is_owner_mismatch else 1,
                'survey_match': 0 if is_survey_mismatch else 1,
                'area_match': 0 if is_area_mismatch else 1,
                'duplicate_property': 1 if is_duplicate else 0,
                'ownership_history_conflict': 1 if is_ownership_conflict else 0,
                'suspicious_transfer_pattern': 1 if is_suspicious_transfer else 0,
                'missing_document': 1 if is_missing_doc else 0,
                'fraud_label': fraud_label,
                'dataset_type': 'Synthetic development/demo dataset',
                'label_noise_applied': 1
            })

        # Property-level ML Dataset Row
        property_ml_rows.append({
            'property_id': prop_id,
            'owner_id': owner_id,
            'owner_name': owner_name,
            'seller_id': seller_id,
            'buyer_id': buyer_id,
            'survey_number': survey_no,
            'land_area': land_area,
            'location': location_str,
            'district': dist,
            'state': state_str,
            'registration_date': reg_date,
            'previous_owner': prev_owner,
            'ownership_transfer_count': transfer_count,
            'document_hash': primary_doc_hash,
            'document_status': 'Hash Mismatch' if is_tampered_hash else 'Verified',
            'owner_match': 0 if is_owner_mismatch else 1,
            'survey_match': 0 if is_survey_mismatch else 1,
            'area_match': 0 if is_area_mismatch else 1,
            'duplicate_property': 1 if is_duplicate else 0,
            'ownership_history_conflict': 1 if is_ownership_conflict else 0,
            'suspicious_transfer_pattern': 1 if is_suspicious_transfer else 0,
            'missing_document': 1 if is_missing_doc else 0,
            # Features for ML Model (8 fraud indicator binary inputs)
            'owner_mismatch': 1 if is_owner_mismatch else 0,
            'survey_mismatch': 1 if is_survey_mismatch else 0,
            'area_mismatch': 1 if is_area_mismatch else 0,
            'hash_mismatch': 1 if is_tampered_hash else 0,
            'fraud_label': fraud_label,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'dataset_type': 'Synthetic development/demo dataset',
            'label_noise_applied': 1
        })

        # Insert alerts into DB
        if is_tampered_hash:
            cursor.execute("""
                INSERT INTO risk_alerts (property_id, alert_type, description, severity, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (prop_id, 'Hash Mismatch', 'SHA-256 document checksum mismatch detected. File content differs from recorded hash.', 'High', reg_date))
        if is_owner_mismatch:
            cursor.execute("""
                INSERT INTO risk_alerts (property_id, alert_type, description, severity, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (prop_id, 'Owner Name Mismatch', 'Review Required — information inconsistency detected in Owner Name.', 'High', reg_date))
        if is_survey_mismatch:
            cursor.execute("""
                INSERT INTO risk_alerts (property_id, alert_type, description, severity, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (prop_id, 'Survey Number Mismatch', 'Review Required — information inconsistency detected in Survey Number.', 'High', reg_date))
        if is_duplicate:
            cursor.execute("""
                INSERT INTO risk_alerts (property_id, alert_type, description, severity, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (prop_id, 'Potential Duplicate Property', 'Matching Survey Number & Village registered across multiple property IDs.', 'High', reg_date))
        if is_missing_doc:
            cursor.execute("""
                INSERT INTO risk_alerts (property_id, alert_type, description, severity, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (prop_id, 'Missing Documentation', 'Primary title documents (Patta / Encumbrance Certificate) not uploaded.', 'Medium', reg_date))

        # Initial Audit Log
        cursor.execute("""
            INSERT INTO audit_logs (user_id, property_id, action, timestamp, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            'SYSTEM', prop_id, 'SYSTEM_INITIALIZATION',
            f"{reg_date} 09:30:00",
            f"Fictional demo property registered. Risk Score: {risk_score} ({risk_level})."
        ))

    # Add demo transfers
    demo_transfers = [
        ('TR-2026-0042', 'RS-PROP-0042', 'USR-1001', 'USR-1002', 'Admin Review', '2026-08-10 11:20:00', 'Transfer submitted, awaiting startup team clearance.'),
        ('TR-2026-0001', 'RS-PROP-0001', 'USR-1001', 'USR-1004', 'Approved', '2026-08-14 14:05:00', 'Clean diligence completed. Pre-transaction safety check passed.'),
        ('TR-2026-0015', 'RS-PROP-0015', 'USR-1003', 'USR-1002', 'Review Required', '2026-08-20 16:30:00', 'Transfer held pending survey number clarification.'),
        ('TR-2026-0031', 'RS-PROP-0031', 'USR-1005', 'USR-1006', 'Review Required', '2026-08-25 09:15:00', 'Transfer flagged due to SHA-256 hash mismatch alert.')
    ]
    for tr in demo_transfers:
        cursor.execute("""
            INSERT INTO transfers (transfer_id, property_id, seller_id, buyer_id, status, created_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, tr)

    conn.commit()
    conn.close()

    # Save to CSVs
    doc_csv_path = os.path.join(DATA_DIR, 'property_documents.csv')
    df_docs = pd.DataFrame(document_csv_rows)
    df_docs.to_csv(doc_csv_path, index=False)

    prop_csv_path = os.path.join(DATA_DIR, 'synthetic_property_fraud_dataset.csv')
    df_props = pd.DataFrame(property_ml_rows)
    df_props.to_csv(prop_csv_path, index=False)

    print(f"Master CSV successfully written to: {doc_csv_path}")
    print(f"Property ML dataset written to: {prop_csv_path}")
    print(f"Total property records generated: {num_properties}")
    print(f"Total document records generated: {len(document_csv_rows)}")
    print(f"Total normal properties: {(df_props['fraud_label'] == 0).sum()}")
    print(f"Total suspicious/fraud properties: {(df_props['fraud_label'] == 1).sum()}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='REALSAFE synthetic dataset tools')
    parser.add_argument('--rebuild-db', action='store_true',
                        help='Wipe SQLite and regenerate all properties (destructive).')
    parser.add_argument('--noise-only', action='store_true',
                        help='Apply investigator label noise to existing CSVs without touching SQLite.')
    args = parser.parse_args()
    if args.noise_only:
        apply_label_noise_to_csv(os.path.join(DATA_DIR, 'synthetic_property_fraud_dataset.csv'))
        apply_label_noise_to_csv(os.path.join(DATA_DIR, 'property_documents.csv'))
    elif args.rebuild_db:
        generate_full_dataset(520)
    else:
        print("Default is non-destructive. Use --noise-only to adjust ML labels, or --rebuild-db to regenerate SQLite.")
        apply_label_noise_to_csv(os.path.join(DATA_DIR, 'synthetic_property_fraud_dataset.csv'))
        apply_label_noise_to_csv(os.path.join(DATA_DIR, 'property_documents.csv'))
