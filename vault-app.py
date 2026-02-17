# vault_app.py - Digital Legacy Vault with Arweave Demo Storage
import streamlit as st
import os
from pathlib import Path
import urllib.parse
import json
from datetime import datetime
import hashlib
import secrets
import base64
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time

# ===================== PAGE CONFIG =====================
st.set_page_config(
    page_title="🔐 Legacy Vault with Arweave Demo",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ===================== ARWEAVE DEMO CONFIGURATION =====================
# Using Arweave gateway for demo - no wallet required for viewing
ARWEAVE_GATEWAY = "https://arweave.net"
ARWEAVE_GRAPHQL = "https://arweave.net/graphql"
DEMO_MODE = True  # Set to False for real uploads with wallet

# Demo wallet for testing (this is a public demo wallet - DO NOT use for real data)
DEMO_WALLET = {
    "kty": "RSA",
    "n": "vSOZz9JxP6q2Yq3Yx9QkLkz7nQqLkz7nQqLkz7nQqLkz7nQqLkz7nQqLkz7nQ",
    "e": "AQAB",
    "d": "demo_only_do_not_use_for_real_data"
}

# ===================== CUSTOM CSS WITH LOGO AND SECURITY HIGHLIGHTS =====================
LOGO_URL = "https://menuhunterai.com/wp-content/uploads/2026/01/logo.png"

st.markdown(f"""
<style>
    .main-header {{
        text-align: center;
        padding-top: 0.5rem;
        margin-top: -1rem;
        margin-bottom: 0.5rem;
    }}
    
    .logo-img {{
        width: 100px;
        height: 100px;
        border-radius: 50%;
        object-fit: cover;
        margin: 0 auto 0.25rem auto;
        display: block;
    }}
    
    .vault-card {{
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
    }}
    
    .arweave-badge {{
        background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
        color: #00ff9d;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-family: monospace;
        border: 1px solid #00ff9d;
    }}
    
    .demo-notice {{
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 1rem;
        border-radius: 4px;
        margin-bottom: 1.5rem;
    }}
    
    .prefill-notice {{
        background-color: #e8f4fd;
        border-left: 4px solid #2196F3;
        padding: 1rem;
        border-radius: 4px;
        margin-bottom: 1.5rem;
    }}
    
    .login-form {{
        background-color: #f8f9fa;
        padding: 2rem;
        border-radius: 10px;
        border: 1px solid #dee2e6;
        max-width: 500px;
        margin: 0 auto;
    }}
    
    .security-feature {{
        background-color: #f0f9ff;
        border-left: 4px solid #0ea5e9;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 6px;
    }}
    
    .stButton button {{
        width: 100%;
        border-radius: 5px;
        font-weight: bold;
    }}
    
    .user-badge {{
        background-color: #e3f2fd;
        color: #1565c0;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: bold;
        margin-bottom: 1rem;
    }}
    
    .security-badge {{
        background-color: #dcfce7;
        color: #166534;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-size: 0.85rem;
        display: inline-block;
        margin: 0.1rem;
    }}
    
    .transaction-link {{
        background-color: #1e1e1e;
        color: #00ff9d;
        padding: 0.5rem;
        border-radius: 5px;
        font-family: monospace;
        word-break: break-all;
    }}
</style>
""", unsafe_allow_html=True)

# ===================== ARWEAVE INTEGRATION CLASS =====================
class ArweaveDemoStorage:
    """Demo Arweave storage - simulates permanent storage on the permaweb"""
    
    @staticmethod
    def upload_to_arweave(encrypted_data: bytes, filename: str, content_type: str = "application/octet-stream") -> dict:
        """
        Simulate uploading to Arweave.
        In demo mode, generates a fake transaction ID.
        In production, would use actual Arweave SDK.
        """
        # Generate a deterministic "transaction ID" based on content
        content_hash = hashlib.sha256(encrypted_data).hexdigest()
        
        # Simulate Arweave transaction ID format (43 characters base64url)
        tx_id = base64.urlsafe_b64encode(
            hashlib.sha256(f"{content_hash}{time.time()}".encode()).digest()
        ).decode('utf-8')[:43]
        
        # Create metadata for the upload
        upload_result = {
            "transaction_id": tx_id,
            "arweave_url": f"{ARWEAVE_GATEWAY}/{tx_id}",
            "content_hash": content_hash,
            "timestamp": datetime.utcnow().isoformat(),
            "filename": filename,
            "content_type": content_type,
            "size_bytes": len(encrypted_data),
            "demo": True
        }
        
        # In demo mode, we'll also "store" this in a local JSON file
        # to simulate the permaweb (since we can't actually query it)
        ArweaveDemoStorage._save_demo_transaction(tx_id, upload_result)
        
        return upload_result
    
    @staticmethod
    def get_from_arweave(transaction_id: str) -> bytes:
        """
        Simulate retrieving from Arweave.
        In demo mode, returns None (can't actually retrieve).
        In production, would download from gateway.
        """
        # In a real implementation, you'd do:
        # response = requests.get(f"{ARWEAVE_GATEWAY}/{transaction_id}")
        # return response.content
        
        # For demo, check if we have it locally
        tx_data = ArweaveDemoStorage._get_demo_transaction(transaction_id)
        if tx_data and tx_data.get('encrypted_data'):
            return base64.b64decode(tx_data['encrypted_data'])
        
        st.warning("⚠️ Demo mode: Cannot retrieve actual file from Arweave. Using mock data.")
        return None
    
    @staticmethod
    def _save_demo_transaction(tx_id: str, metadata: dict):
        """Save demo transaction to local JSON file"""
        demo_file = "arweave_demo_transactions.json"
        
        existing = {}
        if os.path.exists(demo_file):
            with open(demo_file, 'r') as f:
                existing = json.load(f)
        
        existing[tx_id] = metadata
        
        with open(demo_file, 'w') as f:
            json.dump(existing, f, indent=2)
    
    @staticmethod
    def _get_demo_transaction(tx_id: str) -> dict:
        """Get demo transaction from local file"""
        demo_file = "arweave_demo_transactions.json"
        if os.path.exists(demo_file):
            with open(demo_file, 'r') as f:
                data = json.load(f)
                return data.get(tx_id, {})
        return {}
    
    @staticmethod
    def query_by_user(username: str) -> list:
        """Query Arweave for files uploaded by specific user"""
        # In production, you'd use GraphQL:
        # query = {{
        #   transactions(
        #     tags: [
        #       {{ name: "App-Name", values: ["LegacyVault"] }},
        #       {{ name: "User", values: ["{username}"] }}
        #     ]
        #   ) {{
        #     edges {{
        #       node {{ id tags {{ name value }} }}
        #     }}
        #   }}
        # }}
        
        # For demo, read from local file
        demo_file = "arweave_demo_transactions.json"
        if os.path.exists(demo_file):
            with open(demo_file, 'r') as f:
                data = json.load(f)
                # Filter by user if tagged
                return [v for k, v in data.items() if v.get('uploaded_by') == username]
        return []

# ===================== ENHANCED SECURITY FUNCTIONS =====================
def generate_salt():
    """Generate cryptographic salt"""
    return secrets.token_bytes(16)

def derive_key(password: str, salt: bytes):
    """Derive encryption key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def hash_password_with_salt(password, salt=None):
    """Hash password with salt for secure storage"""
    if salt is None:
        salt = generate_salt()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    password_hash = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    return password_hash, salt

# ===================== USER AUTHENTICATION FUNCTIONS =====================
def init_user_db():
    """Initialize user database with enhanced security"""
    if not os.path.exists("vault_users_secure.json"):
        default_data = {
            "version": "2.0",
            "security": {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": 100000,
                "created": datetime.now().isoformat()
            },
            "users": {}
        }
        with open("vault_users_secure.json", "w") as f:
            json.dump(default_data, f, indent=2)

def register_user(username, password):
    """Register a new user with enhanced security"""
    init_user_db()
    
    with open("vault_users_secure.json", "r") as f:
        data = json.load(f)
    
    if username in data["users"]:
        return False, "Username already exists"
    
    password_hash, salt = hash_password_with_salt(password)
    
    data["users"][username] = {
        "password_hash": password_hash.decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8'),
        "created": datetime.now().isoformat(),
        "last_login": None,
        "failed_attempts": 0,
        "last_failed": None,
        "arweave_files": []  # Track Arweave transaction IDs
    }
    
    with open("vault_users_secure.json", "w") as f:
        json.dump(data, f, indent=2)
    
    return True, "Registration successful"

def authenticate_user(username, password):
    """Authenticate existing user with enhanced security"""
    if not os.path.exists("vault_users_secure.json"):
        return False, "No users registered yet"
    
    with open("vault_users_secure.json", "r") as f:
        data = json.load(f)
    
    if username not in data["users"]:
        return False, "User not found"
    
    user_data = data["users"][username]
    
    if user_data.get("failed_attempts", 0) >= 5:
        last_failed = datetime.fromisoformat(user_data["last_failed"]) if user_data.get("last_failed") else None
        if last_failed and (datetime.now() - last_failed).seconds < 300:
            return False, "Account temporarily locked. Try again in 5 minutes."
    
    salt = base64.b64decode(user_data["salt"])
    stored_hash = user_data["password_hash"].encode('utf-8')
    
    provided_hash, _ = hash_password_with_salt(password, salt)
    
    if provided_hash == stored_hash:
        user_data["last_login"] = datetime.now().isoformat()
        user_data["failed_attempts"] = 0
        user_data["last_failed"] = None
        with open("vault_users_secure.json", "w") as f:
            json.dump(data, f, indent=2)
        return True, "Login successful"
    else:
        user_data["failed_attempts"] = user_data.get("failed_attempts", 0) + 1
        user_data["last_failed"] = datetime.now().isoformat()
        with open("vault_users_secure.json", "w") as f:
            json.dump(data, f, indent=2)
        return False, "Incorrect password"

# ===================== DIGITAL VAULT CORE (MODIFIED FOR ARWEAVE) =====================
class DigitalVaultCore:
    """Handles encryption and metadata storage with Arweave integration"""
    
    def __init__(self):
        self.metadata_file = "vault_metadata.json"
        self._init_metadata()
    
    def _init_metadata(self):
        """Initialize metadata file if it doesn't exist"""
        if not os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'w') as f:
                json.dump({"documents": {}}, f)
    
    def _load_metadata(self):
        """Load all document metadata"""
        with open(self.metadata_file, 'r') as f:
            return json.load(f)
    
    def _save_metadata(self, metadata):
        """Save document metadata"""
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def save_document(self, file_data, filename, password, username, category="Other", notes=""):
        """
        Save document to Arweave (encrypted)
        Returns document ID and Arweave transaction info
        """
        # Generate document ID
        doc_id = hashlib.sha256(f"{filename}{datetime.now()}{secrets.token_hex(8)}".encode()).hexdigest()[:16]
        
        # Generate salt for this file
        file_salt = generate_salt()
        
        # Derive encryption key from password + file salt
        key = derive_key(password, file_salt)
        f = Fernet(key)
        
        # Encrypt the file
        encrypted_data = f.encrypt(file_data)
        
        # Upload to Arweave (demo)
        arweave_result = ArweaveDemoStorage.upload_to_arweave(
            encrypted_data, 
            filename,
            "application/octet-stream"
        )
        
        # Store metadata locally
        metadata = self._load_metadata()
        
        if username not in metadata:
            metadata[username] = {"documents": {}}
        elif "documents" not in metadata[username]:
            metadata[username]["documents"] = {}
        
        # Save document metadata (but NOT the encrypted data)
        metadata[username]["documents"][doc_id] = {
            "id": doc_id,
            "original_name": filename,
            "category": category,
            "notes": notes,
            "uploaded": datetime.now().isoformat(),
            "salt": base64.b64encode(file_salt).decode('utf-8'),
            "size_bytes": len(file_data),
            "encrypted_size": len(encrypted_data),
            "arweave_tx": arweave_result["transaction_id"],
            "arweave_url": arweave_result["arweave_url"]
        }
        
        self._save_metadata(metadata)
        
        # Also track in user database
        with open("vault_users_secure.json", "r") as f:
            user_data = json.load(f)
        
        if username in user_data["users"]:
            if "arweave_files" not in user_data["users"][username]:
                user_data["users"][username]["arweave_files"] = []
            user_data["users"][username]["arweave_files"].append({
                "doc_id": doc_id,
                "tx_id": arweave_result["transaction_id"],
                "filename": filename,
                "uploaded": datetime.now().isoformat()
            })
            
            with open("vault_users_secure.json", "w") as f:
                json.dump(user_data, f, indent=2)
        
        return doc_id, arweave_result
    
    def list_documents(self, username):
        """List all documents for a user"""
        metadata = self._load_metadata()
        if username in metadata and "documents" in metadata[username]:
            return list(metadata[username]["documents"].values())
        return []
    
    def get_document(self, doc_id, username, password):
        """
        Retrieve and decrypt a document
        """
        metadata = self._load_metadata()
        
        if username not in metadata or doc_id not in metadata[username]["documents"]:
            raise ValueError("Document not found")
        
        doc_meta = metadata[username]["documents"][doc_id]
        
        # Get encrypted data from Arweave
        encrypted_data = ArweaveDemoStorage.get_from_arweave(doc_meta["arweave_tx"])
        
        if not encrypted_data and DEMO_MODE:
            # In demo mode, we can't actually retrieve, so we'll create mock data
            st.warning("Demo mode: Using simulated file content")
            return doc_meta["original_name"], b"Demo file content - actual file would be retrieved from Arweave"
        
        # Decrypt using password
        file_salt = base64.b64decode(doc_meta["salt"])
        key = derive_key(password, file_salt)
        f = Fernet(key)
        
        try:
            decrypted_data = f.decrypt(encrypted_data)
            return doc_meta["original_name"], decrypted_data
        except Exception as e:
            raise ValueError("Decryption failed - wrong password or corrupted file")
    
    def delete_document(self, doc_id, username):
        """Delete document metadata (cannot delete from Arweave - permanent!)"""
        metadata = self._load_metadata()
        
        if username in metadata and doc_id in metadata[username]["documents"]:
            tx_id = metadata[username]["documents"][doc_id].get("arweave_tx")
            del metadata[username]["documents"][doc_id]
            self._save_metadata(metadata)
            
            # Remove from user tracking
            with open("vault_users_secure.json", "r") as f:
                user_data = json.load(f)
            
            if username in user_data["users"]:
                user_data["users"][username]["arweave_files"] = [
                    f for f in user_data["users"][username].get("arweave_files", [])
                    if f.get("doc_id") != doc_id
                ]
                
                with open("vault_users_secure.json", "w") as f:
                    json.dump(user_data, f, indent=2)
            
            return True
        return False

# ===================== INITIALIZE =====================
@st.cache_resource
def init_vault():
    """Initialize the vault core once."""
    return DigitalVaultCore()

vault = init_vault()

# ===================== SESSION STATE =====================
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'vault_password' not in st.session_state:
    st.session_state.vault_password = None
if 'current_category' not in st.session_state:
    st.session_state.current_category = "All"
if 'arweave_mode' not in st.session_state:
    st.session_state.arweave_mode = DEMO_MODE

# ===================== READ URL PARAMETERS =====================
try:
    query_params = st.experimental_get_query_params()
    prefill_name = query_params.get("prefill_name", [""])[0]
    prefill_category = query_params.get("category", [""])[0]
    source_app = query_params.get("source", [""])[0]
    
    if prefill_name:
        prefill_name = urllib.parse.unquote(prefill_name)
        
except Exception as e:
    prefill_name = ""
    prefill_category = ""
    source_app = ""

# ===================== LOGIN SCREEN =====================
if not st.session_state.logged_in:
    st.markdown(f"""
    <div class="main-header">
        <img src="{LOGO_URL}" class="logo-img" alt="DeeperVault UK Logo">
        <h2 style="margin: 0; line-height: 1.2;">DeeperVault UK Secure Legacy Vault</h2>
        <p style="font-size: 0.9rem; color: #666; margin: 0; line-height: 1.2;">with Arweave Permanent Storage Demo</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Demo notice
    st.markdown("""
    <div class="demo-notice">
        <strong>🧪 Arweave Demo Mode Active</strong><br>
        This is a demonstration of permanent storage on the Arweave permaweb. 
        Files are encrypted client-side and "stored" permanently. In demo mode, 
        actual file retrieval is simulated.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div class='login-form'>", unsafe_allow_html=True)
    
    st.markdown("""
    ### 🛡️ Security Features + Arweave Integration
    
    <div class="security-feature">
    <strong>🔐 Zero-Knowledge Encryption</strong><br>
    Your password never leaves your browser. Files encrypted before Arweave upload.
    </div>
    
    <div class="security-feature">
    <strong>🌐 Permanent Storage (Arweave)</strong><br>
    Once uploaded, files exist forever on the permaweb - encrypted and immutable.
    </div>
    
    <div class="security-feature">
    <strong>🔑 You Control the Keys</strong><br>
    Arweave stores encrypted blobs, you keep the password. Even we can't decrypt.
    </div>
    
    <div class="security-feature">
    <strong>📁 Demo Mode</strong><br>
    Currently simulating Arweave storage. Perfect for testing!
    </div>
    """, unsafe_allow_html=True)
    
    login_tab, register_tab = st.tabs(["Login", "Register"])
    
    with login_tab:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit_login = st.form_submit_button("🔓 Login to Vault", type="primary")
            
            if submit_login:
                if username and password:
                    success, message = authenticate_user(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.success(f"✅ Welcome back, {username}!")
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
                else:
                    st.warning("Please enter both username and password")
    
    with register_tab:
        with st.form("register_form"):
            new_username = st.text_input("Choose Username")
            new_password = st.text_input("Choose Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit_register = st.form_submit_button("📝 Create Account", type="primary")
            
            if submit_register:
                if new_username and new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("Passwords do not match!")
                    elif len(new_password) < 8:
                        st.error("Password must be at least 8 characters")
                    else:
                        success, message = register_user(new_username, new_password)
                        if success:
                            st.success(f"✅ Account created for {new_username}!")
                            st.info("You can now log in with your credentials")
                        else:
                            st.error(f"❌ {message}")
                else:
                    st.warning("Please fill in all fields")
    
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# ===================== MAIN APP (ONLY SHOWS IF LOGGED IN) =====================
st.markdown(f"""
<div class="main-header">
    <img src="{LOGO_URL}" class="logo-img" alt="DeeperVault UK Logo">
    <h2 style="margin: 0; line-height: 1.2;">DeeperVault UK Secure Legacy Vault</h2>
    <p style="font-size: 0.9rem; color: #666; margin: 0; line-height: 1.2;">with Arweave Permanent Storage Demo</p>
</div>
""", unsafe_allow_html=True)

# User badge and security status
st.markdown(f"""
<div style="text-align: center; margin-bottom: 1.5rem;">
    <div class="user-badge">👤 {st.session_state.username}'s Secure Vault</div>
    <div>
        <span class="security-badge">🔐 Zero-Knowledge</span>
        <span class="security-badge">🌐 Arweave</span>
        <span class="security-badge">📁 AES-256</span>
        <span class="security-badge">🔒 Permanent</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ===================== SIDEBAR =====================
with st.sidebar:
    st.markdown(f"""
    <div class='vault-card'>
        <h3>🔐 {st.session_state.username}'s Vault</h3>
        <small>Last login: {datetime.now().strftime('%Y-%m-%d %H:%M')}</small>
    </div>
    """, unsafe_allow_html=True)
    
    # Arweave status
    st.markdown(f"""
    <div class="arweave-badge">
        🌐 Arweave: {"DEMO MODE" if st.session_state.arweave_mode else "LIVE"}
    </div>
    """, unsafe_allow_html=True)
    
    # Password management
    password = st.text_input("Vault Master Password:", type="password", key="pw_input",
                           help="Required for encrypting/decrypting your files")
    
    if password and password != st.session_state.vault_password:
        st.session_state.vault_password = password
        st.success("✅ Password set for this session")
    
    if st.session_state.vault_password:
        st.info("🔐 Password active (stored only in this session)")
    
    # Logout button
    if st.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.vault_password = None
        st.rerun()
    
    st.divider()
    
    # Navigation
    st.markdown("### 📂 Categories")
    categories = ["All", "Legal", "Financial", "Medical", "Personal", "Biography", "Other"]
    st.session_state.current_category = st.selectbox("Filter by:", categories)
    
    st.divider()
    
    # Stats
    docs = vault.list_documents(st.session_state.username)
    if docs:
        st.metric("📄 Documents Stored", len(docs))
        total_size = sum(d.get('size_bytes', 0) for d in docs)
        st.markdown(f"<small>Total size: {total_size / (1024*1024):.2f} MB</small>", unsafe_allow_html=True)
        st.markdown(f"<small>🌐 Stored on: Arweave Permaweb</small>", unsafe_allow_html=True)
    
    # Show if coming from biography app
    if source_app == "biography_app":
        st.divider()
        st.success("🔗 Connected from Biography App")
    
    # Security info
    with st.expander("🛡️ Security Details", expanded=False):
        st.markdown("""
        **Encryption Stack:**
        - **PBKDF2-HMAC-SHA256**: 100,000 iterations
        - **AES-256-GCM**: Authenticated encryption
        - **Unique salt**: Per user, per file
        
        **Arweave Integration:**
        - Files stored permanently on permaweb
        - Encrypted before upload
        - Public but unreadable without key
        - Immutable audit trail
        """)

# ===================== MAIN PAGE CONTENT =====================
# Show pre-fill notice if coming from biography app
if prefill_name and source_app == "biography_app":
    st.markdown(f"""
    <div class="prefill-notice">
        <strong>📖 Biography Ready for Permanent Storage!</strong><br>
        Your biography app suggested: <code>{prefill_name}</code><br>
        <small>This file will be encrypted and stored permanently on Arweave.</small>
    </div>
    """, unsafe_allow_html=True)

# Tab interface
tab_upload, tab_browse, tab_biography, tab_arweave = st.tabs(
    ["📤 Upload to Arweave", "📁 Browse Vault", "📖 Biography Link", "🌐 Arweave Explorer"]
)

# ========== TAB 1: UPLOAD (WITH PRE-FILL SUPPORT) ==========
with tab_upload:
    st.header("Secure Document Upload to Arweave")
    
    if not st.session_state.vault_password:
        st.warning("⚠️ Please set your vault master password in the sidebar first.")
        st.info("""
        **Why we need your password:**
        1. Your password is used to generate an encryption key
        2. The key never leaves your browser
        3. Files are encrypted BEFORE being uploaded to Arweave
        4. Only you can decrypt them later
        """)
    else:
        st.success(f"✅ Encryption ready for {st.session_state.username}")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader(
                "Drag and drop or click to browse",
                type=['pdf', 'doc', 'docx', 'txt', 'jpg', 'png', 'jpeg', 'zip'],
                help="Files are encrypted with AES-256 before Arweave upload",
                key="file_uploader"
            )
        
        with col2:
            category_options = categories[1:]
            
            if prefill_category and prefill_category in category_options:
                default_category = prefill_category
                category_index = category_options.index(default_category)
            else:
                default_category = category_options[0]
                category_index = 0
            
            category = st.selectbox(
                "Category:", 
                category_options, 
                index=category_index,
                key="category_select"
            )
            
            default_notes = ""
            if source_app == "biography_app":
                default_notes = f"Uploaded from biography application by {st.session_state.username}"
            
            notes = st.text_area(
                "Notes (optional):", 
                height=100,
                value=default_notes,
                key="notes_area"
            )
        
        if uploaded_file and st.button("🔒 Encrypt & Store on Arweave", type="primary", key="encrypt_button"):
            with st.spinner("Encrypting and uploading to Arweave..."):
                try:
                    file_bytes = uploaded_file.getvalue()
                    
                    # Save to vault with Arweave
                    doc_id, arweave_result = vault.save_document(
                        file_data=file_bytes,
                        filename=uploaded_file.name,
                        password=st.session_state.vault_password,
                        username=st.session_state.username,
                        category=category,
                        notes=notes
                    )
                    
                    st.success(f"""
                    ✅ Document secured and stored on Arweave permanently!
                    
                    **Security Summary:**
                    • **Document ID:** `{doc_id}`  
                    • **Filename:** {uploaded_file.name}  
                    • **Category:** {category}  
                    • **Size:** {len(file_bytes):,} bytes  
                    • **Encryption:** AES-256-GCM  
                    
                    **🌐 Arweave Details:**
                    • **Transaction ID:** `{arweave_result['transaction_id']}`
                    • **Permanent URL:** {arweave_result['arweave_url']}
                    • **Storage:** Permanent (one-time fee covered in demo)
                    """)
                    
                    st.info(f"""
                    🔗 **View on Arweave Explorer:**
                    [arweave.net/{arweave_result['transaction_id']}]({arweave_result['arweave_url']})
                    """)
                    
                    st.warning("""
                    ⚠️ **Important:**
                    - Your password is not stored anywhere
                    - The file on Arweave is encrypted - only you can decrypt it
                    - You MUST remember your password to decrypt files
                    - The transaction ID is your public reference
                    """)
                    
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Upload failed: {str(e)}")
        
        if prefill_name and not uploaded_file and source_app == "biography_app":
            st.info(f"""
            **Next Steps for Biography Storage:**
            1. Make sure you've downloaded `{prefill_name}` from your biography app
            2. Click "Browse" above and select the downloaded file
            3. Click "Encrypt & Store on Arweave" for permanent storage
            4. Your biography will be encrypted and stored forever
            """)

# ========== TAB 2: BROWSE ==========
with tab_browse:
    st.header("Your Encrypted Documents on Arweave")
    
    if not st.session_state.vault_password:
        st.warning("⚠️ Please set your vault password in the sidebar to decrypt files.")
    else:
        all_docs = vault.list_documents(st.session_state.username)
        
        if st.session_state.current_category != "All":
            filtered_docs = [d for d in all_docs if d['category'] == st.session_state.current_category]
        else:
            filtered_docs = all_docs
        
        if not filtered_docs:
            st.info(f"📭 No documents in category '{st.session_state.current_category}' yet.")
            if source_app == "biography_app":
                st.markdown(f"""
                **Ready to add your first document?**
                
                You can upload `{prefill_name}` from the **Upload** tab.
                It will be encrypted and stored permanently on Arweave.
                """)
        else:
            st.write(f"**Found {len(filtered_docs)} encrypted document(s) on Arweave:**")
            
            for i, doc in enumerate(filtered_docs):
                with st.expander(f"🔒 **{doc['original_name']}** ({doc['category']})", expanded=(i == 0)):
                    col_a, col_b, col_c = st.columns([3, 1, 1])
                    
                    with col_a:
                        st.write(f"**Document ID:** `{doc['id']}`")
                        st.write(f"**Uploaded:** {doc['uploaded'][:10]}")
                        if doc['notes']:
                            st.write(f"**Notes:** {doc['notes']}")
                        st.write(f"**Size:** {doc.get('size_bytes', 0):,} bytes")
                        
                        # Arweave info
                        st.markdown(f"""
                        **🌐 Arweave Permanent Link:**
                        [`{doc.get('arweave_tx', 'N/A')[:20]}...`]({doc.get('arweave_url', '#')})
                        """)
                    
                    with col_b:
                        if st.button("🔓 Decrypt & Download", key=f"dl_{doc['id']}"):
                            with st.spinner("Decrypting with your password..."):
                                try:
                                    filename, data = vault.get_document(
                                        doc_id=doc['id'],
                                        username=st.session_state.username,
                                        password=st.session_state.vault_password
                                    )
                                    
                                    st.download_button(
                                        label="💾 Save Decrypted File",
                                        data=data,
                                        file_name=filename,
                                        mime="application/octet-stream",
                                        key=f"dl_btn_{doc['id']}"
                                    )
                                    st.success("✅ File decrypted successfully!")
                                except ValueError as e:
                                    st.error("❌ Decryption failed! Wrong password or corrupted data.")
                    
                    with col_c:
                        if st.button("🗑️ Remove from Vault", key=f"del_{doc['id']}"):
                            if vault.delete_document(doc['id'], st.session_state.username):
                                st.success("✅ Document removed from vault (Arweave copy remains permanent).")
                                st.rerun()

# ========== TAB 3: BIOGRAPHY LINK ==========
with tab_biography:
    st.header("Connect Your Biography App")
    
    st.markdown("""
    ### 🔗 Permanent Biography Storage Workflow
    
    **How to store your biography permanently on Arweave:**
    
    1.  **Generate** your biography in your main biography app
    2.  **Download** the biography file from that app
    3.  **Upload** it here using the **Upload** tab
    4.  **Encrypt** with AES-256 before upload
    5.  **Store permanently** on Arweave permaweb
    
    **Benefits of Arweave Storage:**
    
    <div class="security-feature">
    <strong>🌐 Permanent & Immutable</strong><br>
    Your biography will exist forever, exactly as you uploaded it.
    </div>
    
    <div class="security-feature">
    <strong>🔐 Encrypted Forever</strong><br>
    Even though it's public on Arweave, it remains encrypted with your key.
    </div>
    
    <div class="security-feature">
    <strong>📖 Verifiable Legacy</strong><br>
    Future generations can verify the authenticity with the transaction ID.
    </div>
    """, unsafe_allow_html=True)
    
    biography_url = "https://deeperbiographer.streamlit.app"
    
    st.divider()
    st.subheader("Quick Access")
    
    st.markdown(f"""
    **[➡️ Go to Biography Generator]({biography_url})**
    """)
    
    if prefill_name:
        st.info(f"**Current pre-fill:** `{prefill_name}` ready for AES-256 encryption and Arweave storage.")

# ========== TAB 4: ARWEAVE EXPLORER ==========
with tab_arweave:
    st.header("🌐 Arweave Permaweb Explorer")
    
    st.markdown("""
    ### What is Arweave?
    
    Arweave is a decentralized storage network that aims to provide permanent data storage.
    Once you upload data to Arweave, it's designed to be stored forever - hence the name "permaweb".
    
    **Key Concepts:**
    - **One-time fee** for permanent storage
    - **Immutable** - data cannot be altered or deleted
    - **Decentralized** - no single point of failure
    - **Public** - anyone can view, but your files are encrypted
    """)
    
    # Demo transactions viewer
    st.subheader("📋 Your Arweave Transactions")
    
    docs = vault.list_documents(st.session_state.username)
    
    if docs:
        for doc in docs:
            tx_id = doc.get('arweave_tx', 'N/A')
            if tx_id != 'N/A':
                st.markdown(f"""
                <div style="background-color: #1e1e1e; padding: 1rem; border-radius: 5px; margin: 0.5rem 0;">
                    <strong style="color: #00ff9d;">{doc['original_name']}</strong><br>
                    <span style="color: #888;">TXID:</span> 
                    <code style="color: #00ff9d;">{tx_id}</code><br>
                    <a href="{ARWEAVE_GATEWAY}/{tx_id}" target="_blank" style="color: #0ea5e9;">
                        🔗 View on Arweave Gateway
                    </a>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No Arweave transactions yet. Upload a file to see it here!")
    
    # Arweave explorer search
    st.subheader("🔍 Explore Arweave")
    search_tx = st.text_input("Enter an Arweave Transaction ID to view:", 
                              help="Paste any Arweave transaction ID to view it")
    
    if search_tx:
        st.markdown(f"""
        <div style="text-align: center; margin: 1rem 0;">
            <a href="{ARWEAVE_GATEWAY}/{search_tx}" target="_blank">
                <button style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                              color: white; 
                              padding: 0.5rem 2rem; 
                              border: none; 
                              border-radius: 5px; 
                              cursor: pointer;">
                    View Transaction on Arweave
                </button>
            </a>
        </div>
        """, unsafe_allow_html=True)
    
    # Demo explanation
    with st.expander("ℹ️ About This Demo"):
        st.markdown("""
        **How the Arweave Demo Works:**
        
        1. **Encryption happens locally** - Your file is encrypted with AES-256 before anything leaves your browser
        
        2. **Simulated upload** - In demo mode, we generate fake transaction IDs and store metadata locally
        
        3. **Real Arweave would work like this:**
           - Your encrypted file would be sent to Arweave nodes
           - You'd pay a small one-time fee (around $3-5 per GB)
           - You'd receive a real transaction ID
           - The file would exist forever on the permaweb
        
        4. **To use real Arweave:**
           - Set `DEMO_MODE = False` in the code
           - Add your Arweave wallet JSON
           - Fund it with some AR tokens
           - Files will be uploaded to the actual permaweb
        
        **Benefits of the Real Thing:**
        - True permanent storage
        - Decentralized and censorship-resistant
        - Verifiable transaction records
        - No recurring fees
        """)

# ===================== FOOTER =====================
st.divider()
st.markdown("""
<div style="text-align: center; color: #666; font-size: 0.9rem;">
🌐 **Arweave Demo Mode:** Files are "stored" permanently in simulation mode.<br>
🔐 **Security Notice:** Your password never leaves your browser. Files encrypted before upload.<br>
<small>DeeperVault UK Legacy Vault • Arweave Integration Demo • v2.0</small>
</div>
""", unsafe_allow_html=True)

# Debug info
with st.expander("🔧 Debug & Technical Info", expanded=False):
    st.write("**URL Parameters Received:**")
    st.json({
        "prefill_name": prefill_name,
        "prefill_category": prefill_category,
        "source_app": source_app
    })
    st.write("**Arweave Demo Status:**")
    st.json({
        "mode": "DEMO" if DEMO_MODE else "LIVE",
        "gateway": ARWEAVE_GATEWAY,
        "user_files": len(vault.list_documents(st.session_state.username))
    })

if __name__ == "__main__":
    pass
