"""
REALSAFE Document Tamper & Hashing Service
Computes SHA-256 hashes using Python hashlib, checks document integrity,
and provides tamper detection utilities.
"""

import hashlib
import os

def compute_sha256_for_file(filepath):
    """Computes and returns the SHA-256 hexadecimal hash of a file."""
    if not os.path.exists(filepath):
        return None
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()

def compute_sha256_for_bytes(data_bytes):
    """Computes and returns the SHA-256 hexadecimal hash of raw bytes."""
    return hashlib.sha256(data_bytes).hexdigest()

def verify_document_hash(filepath, stored_hash):
    """
    Compares the current file SHA-256 hash against the stored hash.
    Returns:
        dict: {
            'is_valid': bool,
            'current_hash': str,
            'stored_hash': str,
            'status': str ('Verified' or 'Document Hash Mismatch')
        }
    """
    current_hash = compute_sha256_for_file(filepath)
    if current_hash is None:
        return {
            'is_valid': False,
            'current_hash': 'FILE_NOT_FOUND',
            'stored_hash': stored_hash,
            'status': 'File Missing'
        }
    
    is_valid = (current_hash.lower() == stored_hash.lower())
    return {
        'is_valid': is_valid,
        'current_hash': current_hash,
        'stored_hash': stored_hash,
        'status': 'DOCUMENT INTEGRITY VERIFIED' if is_valid else 'DOCUMENT TAMPERING DETECTED',
        'explanation': 'SHA-256 verifies whether the file content has changed relative to the previously recorded hash.'
    }

def simulate_tampering(filepath):
    """
    Appends a small comment/byte alteration to a file to simulate
    post-registration document tampering for demonstration purposes.
    """
    if os.path.exists(filepath):
        with open(filepath, 'a', encoding='utf-8', errors='ignore') as f:
            f.write("\n<!-- SIMULATED_TAMPERING_UNAUTHORIZED_ALTERATION -->\n")
        return True
    return False

def restore_clean_file(filepath, clean_text_content):
    """Restores a mock file to its clean state."""
    with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
        f.write(clean_text_content)
    return compute_sha256_for_file(filepath)


def safe_upload_path(upload_folder, filename):
    """Resolve a filename inside upload_folder; reject path traversal."""
    if not filename:
        return None
    name = os.path.basename(str(filename))
    if not name or name in ('.', '..'):
        return None
    root = os.path.abspath(upload_folder)
    path = os.path.abspath(os.path.join(root, name))
    try:
        if os.path.commonpath([root, path]) != root:
            return None
    except ValueError:
        return None
    return path
