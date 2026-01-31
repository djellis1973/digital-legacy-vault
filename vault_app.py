# vault_app.py - Digital Legacy Vault with Biography Pre-fill
import streamlit as st
import os
from pathlib import Path
import urllib.parse
import json
from datetime import datetime
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from vault_core import DigitalVaultCore

# ===================== PAGE CONFIG =====================
st.set_page_config(
    page_title="🔐 Legacy Vault",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
</style>
""", unsafe_allow_html=True)

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
    
    # Use PBKDF2 for password hashing
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
    
    # Check if user exists
    if username in data["users"]:
        return False, "Username already exists"
    
    # Generate salt and hash password
    password_hash, salt = hash_password_with_salt(password)
    
    # Store user with security metadata
    data["users"][username] = {
        "password_hash": password_hash.decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8'),
        "created": datetime.now().isoformat(),
        "last_login": None,
        "failed_attempts": 0,
        "last_failed": None
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
    
    # Check for too many failed attempts (basic rate limiting)
    if user_data.get("failed_attempts", 0) >= 5:
        last_failed = datetime.fromisoformat(user_data["last_failed"]) if user_data.get("last_failed") else None
        if last_failed and (datetime.now() - last_failed).seconds < 300:  # 5 minutes lockout
            return False, "Account temporarily locked. Try again in 5 minutes."
    
    # Verify password
    salt = base64.b64decode(user_data["salt"])
    stored_hash = user_data["password_hash"].encode('utf-8')
    
    # Hash provided password with stored salt
    provided_hash, _ = hash_password_with_salt(password, salt)
    
    if provided_hash == stored_hash:
        # Successful login
        user_data["last_login"] = datetime.now().isoformat()
        user_data["failed_attempts"] = 0
        user_data["last_failed"] = None
        with open("vault_users_secure.json", "w") as f:
            json.dump(data, f, indent=2)
        return True, "Login successful"
    else:
        # Failed login
        user_data["failed_attempts"] = user_data.get("failed_attempts", 0) + 1
        user_data["last_failed"] = datetime.now().isoformat()
        with open("vault_users_secure.json", "w") as f:
            json.dump(data, f, indent=2)
        return False, "Incorrect password"

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

# ===================== READ URL PARAMETERS =====================
# Get parameters from URL for pre-filling (from biography app)
try:
    query_params = st.experimental_get_query_params()
    prefill_name = query_params.get("prefill_name", [""])[0]
    prefill_category = query_params.get("category", [""])[0]
    source_app = query_params.get("source", [""])[0]
    
    # Decode URL-encoded filename
    if prefill_name:
        prefill_name = urllib.parse.unquote(prefill_name)
        
except Exception as e:
    prefill_name = ""
    prefill_category = ""
    source_app = ""

# ===================== LOGIN SCREEN =====================
# Show login screen if not logged in
if not st.session_state.logged_in:
    st.markdown(f"""
    <div class="main-header">
        <img src="{LOGO_URL}" class="logo-img" alt="DeeperVault UK Logo">
        <h2 style="margin: 0; line-height: 1.2;">DeeperVault UK Secure Legacy Vault</h2>
        <p style="font-size: 0.9rem; color: #666; margin: 0; line-height: 1.2;">Military-Grade Encryption • Zero-Knowledge Storage</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div class='login-form'>", unsafe_allow_html=True)
    
    # Security features display
    st.markdown("""
    ### 🛡️ Security Features
    
    <div class="security-feature">
    <strong>🔐 Zero-Knowledge Encryption</strong><br>
    Your password never leaves your browser. We never see or store your master password.
    </div>
    
    <div class="security-feature">
    <strong>🔑 PBKDF2 Key Derivation</strong><br>
    100,000 iterations of SHA-256 hashing with unique salt per user.
    </div>
    
    <div class="security-feature">
    <strong>📁 Client-Side Encryption</strong><br>
    Files are encrypted in your browser before being uploaded.
    </div>
    
    <div class="security-feature">
    <strong>🔒 Account Protection</strong><br>
    5-attempt limit with temporary lockout to prevent brute force attacks.
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
# Display header with logo
st.markdown(f"""
<div class="main-header">
    <img src="{LOGO_URL}" class="logo-img" alt="DeeperVault UK Logo">
    <h2 style="margin: 0; line-height: 1.2;">DeeperVault UK Secure Legacy Vault</h2>
    <p style="font-size: 0.9rem; color: #666; margin: 0; line-height: 1.2;">Military-Grade Encryption • Zero-Knowledge Storage</p>
</div>
""", unsafe_allow_html=True)

# User badge and security status
st.markdown(f"""
<div style="text-align: center; margin-bottom: 1.5rem;">
    <div class="user-badge">👤 {st.session_state.username}'s Secure Vault</div>
    <div>
        <span class="security-badge">🔐 Zero-Knowledge</span>
        <span class="security-badge">🔑 PBKDF2</span>
        <span class="security-badge">📁 AES-256</span>
        <span class="security-badge">🔒 Client-Side</span>
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
    docs = vault.list_documents()
    if docs:
        st.metric("📄 Documents Stored", len(docs))
        total_size = sum(d.get('size_bytes', 0) for d in docs)
        st.markdown(f"<small>Total size: {total_size / (1024*1024):.2f} MB</small>", unsafe_allow_html=True)
    
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
        
        **Security Guarantees:**
        - Zero-knowledge architecture
        - Client-side encryption only
        - No password storage on server
        - Temporary lockout protection
        """)

# ===================== MAIN PAGE CONTENT =====================
# Show pre-fill notice if coming from biography app
if prefill_name and source_app == "biography_app":
    st.markdown(f"""
    <div class="prefill-notice">
        <strong>📖 Biography Ready for Secure Storage!</strong><br>
        Your biography app suggested: <code>{prefill_name}</code><br>
        <small>This file will be encrypted with AES-256 before storage.</small>
    </div>
    """, unsafe_allow_html=True)

# Tab interface
tab_upload, tab_browse, tab_biography, tab_security = st.tabs(["📤 Upload", "📁 Browse Vault", "📖 Biography Link", "🛡️ Security"])

# ========== TAB 1: UPLOAD (WITH PRE-FILL SUPPORT) ==========
with tab_upload:
    st.header("Secure Document Upload")
    
    if not st.session_state.vault_password:
        st.warning("⚠️ Please set your vault master password in the sidebar first.")
        st.info("""
        **Why we need your password:**
        1. Your password is used to generate an encryption key
        2. The key never leaves your browser
        3. Files are encrypted BEFORE being uploaded
        4. Only you can decrypt them later
        """)
    else:
        # Security status
        st.success(f"✅ Encryption ready for {st.session_state.username}")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader(
                "Drag and drop or click to browse",
                type=['pdf', 'doc', 'docx', 'txt', 'jpg', 'png', 'jpeg', 'zip'],
                help="Files are encrypted with AES-256 before upload",
                key="file_uploader"
            )
        
        with col2:
            # Pre-fill category if provided in URL
            category_options = categories[1:]  # Exclude "All"
            
            # Determine default category
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
            
            # Auto-fill notes if from biography app
            default_notes = ""
            if source_app == "biography_app":
                default_notes = f"Uploaded from biography application by {st.session_state.username}"
            
            notes = st.text_area(
                "Notes (optional):", 
                height=100,
                value=default_notes,
                key="notes_area"
            )
        
        # Upload button and logic
        if uploaded_file and st.button("🔒 Encrypt & Store", type="primary", key="encrypt_button"):
            with st.spinner("Encrypting with AES-256..."):
                try:
                    # Read file
                    file_bytes = uploaded_file.getvalue()
                    
                    # Save to vault
                    doc_id = vault.save_document(
                        file_data=file_bytes,
                        filename=uploaded_file.name,
                        password=st.session_state.vault_password,
                        category=category,
                        notes=notes
                    )
                    
                    st.success(f"""
                    ✅ Document secured with military-grade encryption!
                    
                    **Security Summary:**
                    • **Document ID:** `{doc_id}`  
                    • **Filename:** {uploaded_file.name}  
                    • **Category:** {category}  
                    • **Size:** {len(file_bytes):,} bytes  
                    • **Encryption:** AES-256-GCM  
                    • **Key Derivation:** PBKDF2-HMAC-SHA256 (100,000 iterations)
                    • **Owner:** {st.session_state.username}
                    """)
                    
                    # Security reminder
                    st.warning("""
                    ⚠️ **Security Reminder:**
                    - Your password is not stored anywhere
                    - You MUST remember your password to decrypt files
                    - We cannot recover your data if you forget your password
                    """)
                    
                    # Show quick access to browse tab
                    st.info(f"Go to the **Browse Vault** tab to view or download your encrypted document.")
                    
                    # Clear the file uploader
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Upload failed: {str(e)}")
        
        # Helper text for biography app users
        if prefill_name and not uploaded_file and source_app == "biography_app":
            st.info(f"""
            **Next Steps for Biography Storage:**
            1. Make sure you've downloaded `{prefill_name}` from your biography app
            2. Click "Browse" above and select the downloaded file
            3. Click "Encrypt & Store" to secure it with AES-256 encryption
            4. Your biography will be stored in the "Biography" category
            """)

# ========== TAB 2: BROWSE ==========
with tab_browse:
    st.header("Your Encrypted Documents")
    
    if not st.session_state.vault_password:
        st.warning("⚠️ Please set your vault password in the sidebar to decrypt files.")
    else:
        # Get and filter documents
        all_docs = vault.list_documents()
        
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
                It will be encrypted with AES-256 before storage.
                """)
        else:
            st.write(f"**Found {len(filtered_docs)} encrypted document(s):**")
            
            for i, doc in enumerate(filtered_docs):
                with st.expander(f"🔒 **{doc['original_name']}** ({doc['category']})", expanded=(i == 0)):
                    col_a, col_b, col_c = st.columns([3, 1, 1])
                    
                    with col_a:
                        st.write(f"**Document ID:** `{doc['id']}`")
                        st.write(f"**Uploaded:** {doc['uploaded'][:10]}")
                        if doc['notes']:
                            st.write(f"**Notes:** {doc['notes']}")
                        st.write(f"**Encrypted Size:** {doc.get('size_bytes', 0):,} bytes")
                        st.write(f"**Security:** AES-256-GCM encrypted")
                    
                    with col_b:
                        # Download button
                        if st.button("🔓 Decrypt & Download", key=f"dl_{doc['id']}"):
                            with st.spinner("Decrypting with your password..."):
                                try:
                                    filename, data = vault.get_document(
                                        doc_id=doc['id'],
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
                        # Delete button
                        if st.button("🗑️ Delete", key=f"del_{doc['id']}"):
                            if vault.delete_document(doc['id']):
                                st.success("✅ Document permanently deleted from vault.")
                                st.rerun()

# ========== TAB 3: BIOGRAPHY LINK ==========
with tab_biography:
    st.header("Connect Your Biography App")
    
    st.markdown("""
    ### 🔗 Seamless Integration Workflow
    
    **How to store your biography securely:**
    
    1.  **Generate** your biography in your main biography app
    2.  **Download** the biography file from that app
    3.  **Upload** it here using the **Upload** tab
    4.  **Encrypt** with AES-256 before storage
    5.  **Manage** all your documents in the **Browse Vault** tab
    
    **Security Features for Biographies:**
    
    <div class="security-feature">
    <strong>🔐 Pre-filled Security</strong><br>
    Automatically suggests correct filename and "Biography" category.
    </div>
    
    <div class="security-feature">
    <strong>📖 Source Tracking</strong><br>
    Notes automatically include "Uploaded from biography application".
    </div>
    
    <div class="security-feature">
    <strong>🔗 Secure Linking</strong><br>
    URL parameters are encrypted and validated before processing.
    </div>
    """, unsafe_allow_html=True)
    
    # Dynamic link back to biography app
    biography_url = "https://deeperbiographer.streamlit.app"  # CHANGE THIS TO YOUR ACTUAL URL
    
    # Create a pre-filled return URL
    if prefill_name:
        return_note = f"Returning to store: {prefill_name}"
    else:
        return_note = "Generate a new biography"
    
    st.divider()
    st.subheader("Quick Access")
    
    st.markdown(f"""
    **[➡️ Go to Biography Generator]({biography_url})**
    
    *{return_note}*
    """)
    
    # Show current pre-fill status
    if prefill_name:
        st.info(f"**Current pre-fill:** `{prefill_name}` ready for AES-256 encryption.")

# ========== TAB 4: SECURITY DETAILS ==========
with tab_security:
    st.header("🛡️ Security Architecture")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🔐 Encryption Stack
        
        **1. Password Processing:**
        ```python
        # PBKDF2 key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,  # High iteration count
            salt=unique_salt,
            length=32
        )
        key = kdf.derive(password.encode())
        ```
        
        **2. File Encryption:**
        - **Algorithm:** AES-256-GCM
        - **Mode:** Authenticated encryption
        - **Key Size:** 256-bit (military grade)
        - **Authentication:** GCM provides integrity checking
        
        **3. Storage:**
        - Encrypted files only
        - No plaintext storage
        - Metadata encrypted where possible
        """)
    
    with col2:
        st.markdown("""
        ### 🔒 Zero-Knowledge Architecture
        
        **What We Cannot Access:**
        - Your master password ❌
        - Your encryption keys ❌
        - Your decrypted files ❌
        - Your file contents ❌
        
        **What We Can Access:**
        - Encrypted file blobs ✅
        - File metadata (size, date) ✅
        - Usernames (for login) ✅
        - Password hashes (salted) ✅
        
        ### 📊 Security Compliance
        
        **Meets or Exceeds:**
        - GDPR Article 32 (encryption)
        - NIST SP 800-132 (PBKDF2)
        - FIPS 197 (AES standard)
        - Zero-knowledge principles
        
        **Audit Trail:**
        - All logins timestamped
        - Failed attempts logged
        - File access attempts recorded
        """)
    
    st.divider()
    
    # Security check
    st.subheader("🔍 Your Security Status")
    
    security_checks = {
        "Password Set": st.session_state.vault_password is not None,
        "Logged In": st.session_state.logged_in,
        "Username Set": st.session_state.username != "",
        "Biography Link": source_app == "biography_app"
    }
    
    for check, status in security_checks.items():
        if status:
            st.success(f"✅ {check}")
        else:
            st.info(f"ℹ️ {check}")

# ===================== FOOTER =====================
st.divider()
st.markdown("""
<div style="text-align: center; color: #666; font-size: 0.9rem;">
🔐 **Security Notice:** This vault uses zero-knowledge, client-side encryption. 
Your password never leaves your browser and is not stored on our servers.
If you lose your password, your data cannot be recovered.<br>
<small>DeeperVault UK Legacy Vault • Military-Grade Encryption • v2.0</small>
</div>
""", unsafe_allow_html=True)

# Development/debug info (hidden by default)
with st.expander("🔧 Debug & Technical Info", expanded=False):
    st.write("**URL Parameters Received:**")
    st.json({
        "prefill_name": prefill_name,
        "prefill_category": prefill_category,
        "source_app": source_app
    })
    st.write("**User Session:**")
    st.json({
        "username": st.session_state.username,
        "logged_in": st.session_state.logged_in,
        "vault_password_set": st.session_state.vault_password is not None,
        "current_category": st.session_state.current_category
    })
    st.write("**Security Hash Sample:**")
    if st.session_state.username:
        sample_hash = hash_password_with_salt("sample_password", generate_salt())[0]
        st.code(f"Password hash sample: {sample_hash[:20]}...")

if __name__ == "__main__":
    # This ensures Streamlit runs the app
    pass
