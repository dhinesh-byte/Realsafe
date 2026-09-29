"""
REALSAFE Database Model & Helper Functions
Manages SQLite database connection and table schema for the REALSAFE platform.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'realsafe.db')

def get_db_connection():
    """Returns a SQLite connection with row factory enabled for dictionary-style access."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initializes the SQLite database with all required tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        verified_user_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'seller',
        verification_status TEXT NOT NULL DEFAULT 'Verified',
        password_hash TEXT NOT NULL DEFAULT 'demo_hash',
        email TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Properties Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS properties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        property_id TEXT UNIQUE NOT NULL,
        owner_id TEXT NOT NULL,
        owner_name TEXT NOT NULL,
        survey_number TEXT NOT NULL,
        land_area REAL NOT NULL,
        area_unit TEXT NOT NULL DEFAULT 'sq.ft',
        property_type TEXT NOT NULL,
        district TEXT NOT NULL,
        taluk TEXT NOT NULL,
        village TEXT NOT NULL,
        location TEXT NOT NULL,
        registration_date TEXT NOT NULL,
        ownership_status TEXT NOT NULL DEFAULT 'Active',
        verification_status TEXT NOT NULL DEFAULT 'Pending',
        risk_score INTEGER NOT NULL DEFAULT 0,
        risk_level TEXT NOT NULL DEFAULT 'Low Risk',
        previous_owner TEXT,
        transfer_date TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Documents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id TEXT UNIQUE NOT NULL,
        property_id TEXT NOT NULL,
        document_type TEXT NOT NULL,
        filename TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        upload_date TEXT NOT NULL,
        verification_status TEXT NOT NULL DEFAULT 'Pending',
        FOREIGN KEY (property_id) REFERENCES properties (property_id) ON DELETE CASCADE
    );
    """)

    # 4. Document Data Table (Extracted/Reported Document Attributes)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS document_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id TEXT UNIQUE NOT NULL,
        owner_name TEXT,
        survey_number TEXT,
        land_area REAL,
        location TEXT,
        registration_date TEXT,
        FOREIGN KEY (document_id) REFERENCES documents (document_id) ON DELETE CASCADE
    );
    """)

    # 5. Ownership History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ownership_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        property_id TEXT NOT NULL,
        owner_name TEXT NOT NULL,
        start_date TEXT NOT NULL,
        end_date TEXT,
        transfer_reference TEXT,
        notes TEXT,
        FOREIGN KEY (property_id) REFERENCES properties (property_id) ON DELETE CASCADE
    );
    """)

    # 6. Transfers Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transfer_id TEXT UNIQUE NOT NULL,
        property_id TEXT NOT NULL,
        seller_id TEXT NOT NULL,
        buyer_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Submitted',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        notes TEXT,
        FOREIGN KEY (property_id) REFERENCES properties (property_id) ON DELETE CASCADE
    );
    """)

    # 7. Risk Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        property_id TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'Medium',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (property_id) REFERENCES properties (property_id) ON DELETE CASCADE
    );
    """)

    # 8. Verification Records Table (Enhanced Audit Trail)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS verification_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        property_id TEXT NOT NULL,
        verification_type TEXT NOT NULL,
        result TEXT NOT NULL,
        checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        details TEXT,
        hash_result TEXT DEFAULT 'Verified',
        mismatch_result TEXT DEFAULT 'Clean',
        ml_prediction TEXT DEFAULT 'Normal',
        ml_probability REAL DEFAULT 0.0,
        risk_score INTEGER DEFAULT 0,
        final_status TEXT DEFAULT 'Verified',
        FOREIGN KEY (property_id) REFERENCES properties (property_id) ON DELETE CASCADE
    );
    """)

    # Check and safely add any missing columns in verification_records if table existed
    cursor.execute("PRAGMA table_info(verification_records)")
    vr_cols = [col[1] for col in cursor.fetchall()]
    for col_name, col_def in [
        ('hash_result', 'TEXT DEFAULT "Verified"'),
        ('mismatch_result', 'TEXT DEFAULT "Clean"'),
        ('ml_prediction', 'TEXT DEFAULT "Normal"'),
        ('ml_probability', 'REAL DEFAULT 0.0'),
        ('risk_score', 'INTEGER DEFAULT 0'),
        ('final_status', 'TEXT DEFAULT "Verified"')
    ]:
        if col_name not in vr_cols:
            try:
                cursor.execute(f"ALTER TABLE verification_records ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass

    # 9. Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        property_id TEXT,
        action TEXT NOT NULL,
        timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        details TEXT
    );
    """)

    # 10. Model Metrics Table (Stores Authentic Scikit-Learn Test Set Evaluations)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS model_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT NOT NULL,
        model_version TEXT NOT NULL,
        training_date TEXT NOT NULL,
        dataset_size INTEGER NOT NULL,
        feature_count INTEGER NOT NULL,
        accuracy REAL NOT NULL,
        precision REAL NOT NULL,
        recall REAL NOT NULL,
        f1_score REAL NOT NULL,
        confusion_matrix TEXT,
        is_primary INTEGER DEFAULT 0,
        notes TEXT
    );
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_properties_property_id ON properties(property_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_properties_risk_score ON properties(risk_score);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_documents_property_id ON documents(property_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_document_data_document_id ON document_data(document_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ownership_property_id ON ownership_history(property_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_transfers_property_id ON transfers(property_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_property_id ON risk_alerts(property_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON risk_alerts(alert_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_verification_property_id ON verification_records(property_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_property_id ON audit_logs(property_id);")

    conn.commit()
    conn.close()

def log_audit(user_id, property_id, action, details=""):
    """Inserts an immutable audit log entry."""
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO audit_logs (user_id, property_id, action, timestamp, details) VALUES (?, ?, ?, ?, ?)",
        (user_id, property_id, action, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), details)
    )
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("REALSAFE database initialized successfully at:", DB_PATH)
