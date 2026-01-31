# vault_core.py - Paste this entire block
import os
import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class DigitalVaultCore:
    def __init__(self, storage_root="vault_storage"):
        self.storage_root = Path(storage_root)
        self.storage_root.mkdir(exist_ok=True)
        self.db_file = self.storage_root / "vault_meta.json"
        self._init_db()
    def _init_db(self):
        if not self.db_file.exists():
            default_db = {"version": "1.0", "created": datetime.now().isoformat(), "documents": []}
            self._save_db(default_db)
    def _load_db(self):
        with open(self.db_file, 'r') as f:
            return json.load(f)
    def _save_db(self, data):
        with open(self.db_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    def encrypt_data(self, plain_data: bytes, password: str) -> dict:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key, _ = self.derive_key(password, salt)
        aesgcm = AESGCM(key)
        cipher_data = aesgcm.encrypt(nonce, plain_data, None)
        return {
            "ciphertext": base64.b64encode(cipher_data).decode('ascii'),
            "salt": base64.b64encode(salt).decode('ascii'),
            "nonce": base64.b64encode(nonce).decode('ascii'),
            "algorithm": "AES-256-GCM"
        }
    def decrypt_data(self, encrypted_package: dict, password: str) -> bytes:
        try:
            ciphertext = base64.b64decode(encrypted_package["ciphertext"])
            salt = base64.b64decode(encrypted_package["salt"])
            nonce = base64.b64decode(encrypted_package["nonce"])
            key, _ = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            plain_data = aesgcm.decrypt(nonce, ciphertext, None)
            return plain_data
        except (InvalidTag, KeyError, ValueError):
            raise ValueError("DECRYPTION FAILED: Wrong password.")
    def save_document(self, file_data: bytes, filename: str, password: str, category: str = "General", notes: str = "") -> str:
        encrypted_pkg = self.encrypt_data(file_data, password)
        doc_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        safe_name = f"enc_{doc_id}.bin"
        blob_path = self.storage_root / safe_name
        with open(blob_path, 'wb') as f:
            f.write(base64.b64decode(encrypted_pkg["ciphertext"]))
        doc_meta = {
            "id": doc_id, "original_name": filename, "safe_name": safe_name,
            "category": category, "notes": notes, "uploaded": datetime.now().isoformat(),
            "size_bytes": len(file_data), "salt": encrypted_pkg["salt"], "nonce": encrypted_pkg["nonce"]
        }
        db = self._load_db()
        db["documents"].append(doc_meta)
        self._save_db(db)
        return doc_id
    def list_documents(self):
        db = self._load_db()
        return db.get("documents", [])
    def get_document(self, doc_id: str, password: str):
        db = self._load_db()
        doc = next((d for d in db["documents"] if d["id"] == doc_id), None)
        if not doc:
            raise FileNotFoundError(f"Document {doc_id} not found.")
        blob_path = self.storage_root / doc["safe_name"]
        with open(blob_path, 'rb') as f:
            ciphertext = f.read()
        encrypted_pkg = {"ciphertext": base64.b64encode(ciphertext).decode('ascii'), "salt": doc["salt"], "nonce": doc["nonce"]}
        decrypted_data = self.decrypt_data(encrypted_pkg, password)
        return doc["original_name"], decrypted_data
    def delete_document(self, doc_id: str):
        db = self._load_db()
        for i, doc in enumerate(db["documents"]):
            if doc["id"] == doc_id:
                blob_path = self.storage_root / doc["safe_name"]
                if blob_path.exists():
                    blob_path.unlink()
                db["documents"].pop(i)
                self._save_db(db)
                return True
        return False
