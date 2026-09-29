# REALSAFE — Digital Real Estate Fraud Detection & Property Verification System

> **"Don't just verify the property. Detect suspicious patterns before the buyer pays."**

REALSAFE is an enterprise-grade digital safety, document verification, and explainable fraud-risk detection platform prototype engineered for proptech platforms, real estate buyers, sellers, registrars, and risk-management compliance officers.

---

## ⚠️ Important Prototype Disclaimer
REALSAFE is a prototype fraud-risk detection and property verification system.
- **Verification Results are Indicators Only:** Algorithmic verification results do NOT constitute legal proof of ownership, certified title clearance, or official government sub-registrar certification.
- **Synthetic Development / Demo Dataset:** All property records, document texts, owner names, user IDs, and survey numbers are strictly synthetic, simulated, and anonymized (520 properties, 1,656 documents). **No real citizen Aadhaar numbers, PAN numbers, phone numbers, or private personal data are stored or processed.**
- **Role Boundary:** REALSAFE is NOT a property listing portal, NOT a legal ownership determination authority, and NOT a replacement for official state revenue land registries.

---

## 1. The Problem Being Solved
Real estate fraud frequently manifests through systemic cadastral and identity vulnerabilities:
1. **Duplicate Property Registrations:** Malicious actors register the same physical land parcel (matching survey numbers, village, and dimensions) under multiple distinct listings or fictitious owner profiles to collect advance payments.
2. **Post-Registration Document Tampering:** Deeds or tax receipts are altered (changing plot boundaries, survey numbers, or names) after legitimate registration.
3. **Cross-Document Discrepancies:** Name variations (e.g., *Arun Kumar* on the title deed vs. *Arjun Kumar* on the Patta revenue record) or survey number typos (`SUR-458/2A` vs. `SUR-458/2B`) concealing disputed boundaries.
4. **Broken Chain of Title & Rapid Flips:** Properties changing hands repeatedly within short timeframes (e.g., < 180 days) to obscure fraudulent transfers.

---

## 2. Four Pillars of Verification Architecture
The system strictly distinguishes between four independent verification layers:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          REALSAFE FOUR PILLARS                          │
├───────────────────┬───────────────────┬─────────────────┬───────────────┤
│  1. RULE-BASED    │  2. MACHINE       │  3. EXPLAINABLE │ 4. CRYPTO     │
│     VERIFICATION  │     LEARNING      │     AI (SHAP)   │    INTEGRITY  │
├───────────────────┼───────────────────┼─────────────────┼───────────────┤
│ • Cadastral cross-│ • Random Forest   │ • Game-theoretic│ • SHA-256     │
│   reconciliation  │   Classifier (100%│   TreeSHAP local│   binary file │
│ • Spatial cluster │   test F1)        │   attribution   │   hashing     │
│   duplicate check │ • Logistic Reg    │ • Plain English │ • Tamper lab  │
│ • Chain-of-title  │   baseline (98.2% │   explanations  │   simulation  │
│   timeline audit  │   test F1)        │   for non-tech  │ • File status │
│ • Missing document│ • Evaluated on 104│   judges/buyers │   ledger      │
│   vault detection │   held-out test   │                 │               │
└───────────────────┴───────────────────┴─────────────────┴───────────────┘
                                   ▼
          COMPOSITE TRANSPARENT RISK ENGINE (0–100 SCORE)
          [0–29 Low | 30–59 Medium | 60–79 High | 80–100 Critical]
```

1. **Rule-Based Verification:** Deterministic checks for cadastral mismatches (Owner Name, Survey Number, Land Area), duplicate parcel clustering, chain-of-title timeline gaps, and missing documents.
2. **Machine Learning Classification:** Supervised pattern recognition evaluating multi-factor risk likelihood.
3. **Explainable AI (SHAP):** TreeSHAP attribution measuring the exact positive/negative push of each feature on the model's prediction with plain English summaries.
4. **Cryptographic Verification (SHA-256):** Byte-level file hashing verifying whether file content has changed relative to the immutable registration ledger. *Proves document integrity, not ownership legality.*

---

## 3. Machine Learning Pipeline & Authentic Benchmark Metrics
A dedicated training pipeline lives in `ml/train_model.py`:
- **Dataset:** 520 synthetic property records (380 Normal / 140 Fraud-like).
- **Split:** Stratified 80% Train (416 samples) / 20% Test (104 samples), `random_state=42`.
- **Features (8):**
  1. `owner_mismatch` — Discrepancy between master record and submitted deeds
  2. `survey_mismatch` — Discrepancy across cadastral survey numbers
  3. `area_mismatch` — Land area variance exceeding 1% tolerance
  4. `duplicate_property` — Overlapping spatial survey boundaries
  5. `hash_mismatch` — SHA-256 cryptographic file mismatch
  6. `ownership_conflict` — Chain-of-title chronological timeline gap
  7. `suspicious_transfer` — Rapid sequential transfers (< 180 days)
  8. `missing_document` — Incomplete primary title vault

### Authentic Test Set Performance (104 Samples)
> **Notice:** All metrics are calculated exclusively on the held-out test set (76 Normal, 28 Fraud-like). Zero hardcoded or fabricated values.

| Model | Accuracy | Precision | Recall | F1-Score | Confusion Matrix (TN, FP, FN, TP) |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Random Forest (Primary)** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | `[[76, 0], [0, 28]]` (Zero errors) |
| **Logistic Regression (Baseline)** | 99.04% | 100.00% | 96.43% | 98.18% | `[[76, 0], [1, 27]]` (1 False Negative) |

**Model Selection Rationale:** Random Forest is chosen because decision trees capture non-linear combinatorial interactions between fraud signals (e.g. rapid flips combined with area variance or hash alteration) and natively integrate with TreeSHAP for exact local game-theoretic attribution.

**Artifacts Persisted:**
- `models/random_forest_model.joblib`
- `models/logistic_regression_model.joblib`
- `models/model_metadata.json`
- SQLite `model_metrics` table

---

## 4. Transparent Risk Scoring Engine (4 Tiers)
The final risk score (0–100) is a deterministic aggregation of verified signals:
- `+30 pts`: Document Hash Mismatch
- `+25 pts`: Owner Name Inconsistency
- `+25 pts`: Survey Number Inconsistency
- `+20 pts`: Potential Duplicate Property
- `+20 pts`: Chain-of-Title / Timeline Conflict
- `+15 pts`: Land Area Inconsistency
- `+15 pts`: Suspicious Rapid Transfer Pattern
- `+10 pts`: Missing Required Document

### Four Risk Tiers
- **0–29: Low Risk (🟢)** — Clean record. All verified signals within normal baseline limits. Transaction may proceed with standard diligence.
- **30–59: Medium Risk (🟡)** — Information inconsistency detected. Review required before the buyer commits funds.
- **60–79: High Risk (🟠)** — Multiple risk indicators detected. Transaction on hold. In-depth physical revenue verification recommended.
- **80–100: Critical Risk (🔴)** — Severe fraud signals or cryptographic tampering detected. Immediate transaction freeze and forensic audit recommended.

> **Distinction Note:** The final risk score (e.g. 78/100) is distinct from the ML suspicious probability (e.g. 87%). ML probability represents pattern recognition, while the risk score incorporates deterministic rule penalties and cryptographic checks.

---

## 5. Three Guided Demo Scenarios
The application makes it easy to demonstrate three core scenarios:

| Scenario | Target Property | Detection Vectors & Expected Results |
| :--- | :--- | :--- |
| **Scenario 1: Genuine Property** | `RS-PROP-0001` | All SHA-256 hashes match. No mismatches. ML Prediction: **Normal** (0.0% prob). Risk Score: **0/100 (Low Risk 🟢)**. Recommendation: Safe to Proceed. |
| **Scenario 2: Tampered Document** | `RS-PROP-0031` | Sale Deed byte alteration on disk. SHA-256 Mismatch flagged: `DOCUMENT TAMPERING DETECTED`. Risk Score: **30/100 (Medium Risk 🟡)**. SHAP highlights Document Hash Tamper Flag (+30 pts). |
| **Scenario 3: Property Mismatch** | `RS-PROP-0007` (Owner) / `RS-PROP-0015` (Survey) | Master Record (*Arun Kumar*) vs Patta (*Arjun Kumar*). Discrepancy flagged. ML Prediction: **Suspicious**. SHAP highlights Owner Name Discrepancy. Risk Score: **25/100**. |

### Additional Benchmark Properties
- `RS-PROP-0023` & `RS-PROP-0087`: Duplicate Property Cluster (same survey number `SUR-882/4C`).
- `RS-PROP-0044`: Timeline Conflict (unexplained gap in ownership dates).
- `RS-PROP-0058`: Multi-Risk Vector (Owner + Survey + Duplicate + Tamper). Score: **100/100 (Critical Risk 🔴)**.
- `RS-PROP-0072`: Incomplete Document Vault (Missing Encumbrance Certificate).
- `RS-PROP-0091`: High Velocity Transfers (Rapid flips within 45 days).
- `RS-PROP-0100`: Clean Reference Benchmark.

---

## 6. REST API Reference

### 1. Multi-Vector Verification
`POST /api/verify-property`
- **Request Body (JSON):**
  ```json
  { "property_id": "RS-PROP-0031" }
  ```
  *(Alternatively accepts custom feature flags: `owner_mismatch`, `survey_mismatch`, etc.)*
- **Response (JSON):**
  ```json
  {
    "property_id": "RS-PROP-0031",
    "ml_prediction": "Suspicious",
    "ml_probability": 0.35,
    "risk_score": 30,
    "risk_status": "Medium Risk",
    "hash_status": "DOCUMENT TAMPERING DETECTED",
    "explanation": [
      "Document Hash Tamper Flag (SHAP +0.285)",
      "Explainable AI – SHAP attributes the Random Forest prediction to active signals."
    ]
  }
  ```

### 2. Property Digital Passport API
`GET /api/property/<property_id>`
- Returns complete passport record, document ledger, ownership history, and active alerts.

### 3. Model Performance Metrics
`GET /api/model-metrics`
- Returns evaluated Random Forest and Logistic Regression test metrics, confusion matrices, parameters, and versioning (`REALSAFE-RF-v1.0`).

### 4. Property Quick Verification
`GET /api/verify/<property_id>`
- Runs full verification pipeline and returns risk score, risk level, and indicators.

---

## 7. Database Architecture (`database/realsafe.db`)
1. `properties` — Master cadastral records, risk scores, verification status.
2. `documents` — Document ledger with SHA-256 hashes, file paths, upload dates.
3. `document_data` — Extracted field values for cross-document reconciliation.
4. `ownership_history` — Chronological chain-of-title records.
5. `transfers` — Safe buyer-seller transfer pipeline.
6. `risk_alerts` — Active discrepancy, duplicate, and tamper alerts.
7. `verification_records` — Enhanced audit log storing `hash_result`, `mismatch_result`, `ml_prediction`, `ml_probability`, `risk_score`, `final_status`.
8. `audit_logs` — Immutable platform event ledger.
9. `model_metrics` — ML model versioning, test metrics, and confusion matrices.
10. `users` — Verified user personas (Seller, Buyer, Admin).

---

## 8. Installation & Execution Guide

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Pip

### Setup Commands
```bash
# 1. Navigate to project root
cd C:\Users\harih\.gemini\antigravity\scratch\realsafe

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate synthetic dataset (520 properties, 1,656 documents)
python generate_dataset.py

# 4. Train and evaluate ML models (Random Forest & Logistic Regression)
python ml/train_model.py

# 5. Run automated test suites
python test_realsafe.py
python test_routes.py

# 6. Start the Flask application
python app.py
```
Open your browser at: **`http://127.0.0.1:5000`**

---

## 9. Limitations & Future Roadmap
- **OCR Integration:** Future production releases will integrate Tesseract OCR or Vision LLMs to extract raw scanned deed text dynamically.
- **State Registration API Gateways:** Direct integration with authorized government land record APIs (such as TNREGINET / Bhoomi).
- **Escrow Integration:** Linking verified status gates to smart contract or bank escrow APIs to hold funds until all pre-transaction safety checks clear.

---

## License
Educational and hackathon prototype developed for demonstrative fraud prevention, explainable AI research, and proptech risk governance.

