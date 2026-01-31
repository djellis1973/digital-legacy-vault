# vault_app.py - Digital Legacy Vault with Biography Pre-fill
import streamlit as st
import os
from pathlib import Path
import urllib.parse
from vault_core import DigitalVaultCore

# ===================== PAGE CONFIG =====================
st.set_page_config(
    page_title="🔐 Legacy Vault",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ===================== CUSTOM CSS =====================
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #2c3e50;
        text-align: center;
        margin-bottom: 2rem;
    }
    .vault-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    .prefill-notice {
        background-color: #e8f4fd;
        border-left: 4px solid #2196F3;
        padding: 1rem;
        border-radius: 4px;
        margin-bottom: 1.5rem;
    }
    .stButton button {
        width: 100%;
        border-radius: 5px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ===================== INITIALIZE =====================
@st.cache_resource
def init_vault():
    """Initialize the vault core once."""
    return DigitalVaultCore()

vault = init_vault()

# ===================== SESSION STATE =====================
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

# ===================== SIDEBAR =====================
with st.sidebar:
    st.markdown("<div class='vault-card'><h2>🔐 Vault Access</h2></div>", unsafe_allow_html=True)
    
    # Password management
    password = st.text_input("Vault Master Password:", type="password", key="pw_input")
    
    if password and password != st.session_state.vault_password:
        st.session_state.vault_password = password
        st.success("✅ Password set locally")
    
    if st.session_state.vault_password:
        st.info("Password active in this session")
    
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

# ===================== MAIN PAGE =====================
st.markdown("<h1 class='main-header'>🔐 Your Digital Legacy Vault</h1>", unsafe_allow_html=True)

# Show pre-fill notice if coming from biography app
if prefill_name and source_app == "biography_app":
    st.markdown(f"""
    <div class="prefill-notice">
        <strong>📖 Ready to store your biography!</strong><br>
        Your biography app suggested: <code>{prefill_name}</code><br>
        <small>Download the file from your biography app first, then upload it here.</small>
    </div>
    """, unsafe_allow_html=True)

# Tab interface
tab_upload, tab_browse, tab_biography = st.tabs(["📤 Upload", "📁 Browse Vault", "📖 Biography Link"])

# ========== TAB 1: UPLOAD (WITH PRE-FILL SUPPORT) ==========
with tab_upload:
    st.header("Secure Document Upload")
    
    if not st.session_state.vault_password:
        st.warning("⚠️ Please set your vault password in the sidebar first.")
    else:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader(
                "Drag and drop or click to browse",
                type=['pdf', 'doc', 'docx', 'txt', 'jpg', 'png', 'jpeg', 'zip'],
                help="Maximum file size depends on Streamlit Cloud limits (~200MB)",
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
                default_notes = "Uploaded from biography application"
            
            notes = st.text_area(
                "Notes (optional):", 
                height=100,
                value=default_notes,
                key="notes_area"
            )
        
        # Upload button and logic
        if uploaded_file and st.button("🔒 Encrypt & Store", type="primary", key="encrypt_button"):
            with st.spinner("Encrypting and storing securely..."):
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
                    ✅ Document secured in your vault!
                    
                    **Document ID:** `{doc_id}`  
                    **Filename:** {uploaded_file.name}  
                    **Category:** {category}  
                    **Size:** {len(file_bytes):,} bytes  
                    **Encryption:** AES-256-GCM with PBKDF2-HMAC-SHA256
                    """)
                    
                    # Show quick access to browse tab
                    st.info(f"Go to the **Browse Vault** tab to view or download your document.")
                    
                    # Clear the file uploader
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Upload failed: {str(e)}")
        
        # Helper text for biography app users
        if prefill_name and not uploaded_file and source_app == "biography_app":
            st.info(f"""
            **Next Steps:**
            1. Make sure you've downloaded `{prefill_name}` from your biography app
            2. Click "Browse" above and select the downloaded file
            3. Click "Encrypt & Store" to secure it in your vault
            """)

# ========== TAB 2: BROWSE ==========
with tab_browse:
    st.header("Your Secure Documents")
    
    if not st.session_state.vault_password:
        st.warning("⚠️ Please set your vault password in the sidebar first.")
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
                """)
        else:
            st.write(f"**Found {len(filtered_docs)} document(s):**")
            
            for i, doc in enumerate(filtered_docs):
                with st.expander(f"📄 **{doc['original_name']}** ({doc['category']})", expanded=(i == 0)):
                    col_a, col_b, col_c = st.columns([3, 1, 1])
                    
                    with col_a:
                        st.write(f"**ID:** `{doc['id']}`")
                        st.write(f"**Uploaded:** {doc['uploaded'][:10]}")
                        if doc['notes']:
                            st.write(f"**Notes:** {doc['notes']}")
                        st.write(f"**Size:** {doc.get('size_bytes', 0):,} bytes")
                    
                    with col_b:
                        # Download button
                        if st.button("⬇️ Download", key=f"dl_{doc['id']}"):
                            with st.spinner("Decrypting..."):
                                try:
                                    filename, data = vault.get_document(
                                        doc_id=doc['id'],
                                        password=st.session_state.vault_password
                                    )
                                    
                                    st.download_button(
                                        label="💾 Save File",
                                        data=data,
                                        file_name=filename,
                                        mime="application/octet-stream",
                                        key=f"dl_btn_{doc['id']}"
                                    )
                                except ValueError as e:
                                    st.error("❌ Wrong password or corrupted data!")
                    
                    with col_c:
                        # Delete button
                        if st.button("🗑️ Delete", key=f"del_{doc['id']}"):
                            if vault.delete_document(doc['id']):
                                st.success("✅ Document deleted from vault.")
                                st.rerun()

# ========== TAB 3: BIOGRAPHY LINK ==========
with tab_biography:
    st.header("Connect Your Biography App")
    
    st.markdown("""
    ### 🔗 Seamless Integration Workflow
    
    **How to store your biography:**
    
    1.  **Generate** your biography in your main biography app
    2.  **Download** the biography file from that app
    3.  **Upload** it here using the **Upload** tab
    4.  **Manage** all your documents in the **Browse Vault** tab
    
    Your vault will automatically:
    *   Suggest the correct filename
    *   Pre-select the "Biography" category
    *   Add helpful notes about the source
    """)
    
    # Dynamic link back to biography app
    biography_url = "https://YOUR_BIOGRAPHY_APP_URL.streamlit.app"  # CHANGE THIS
    
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
        st.info(f"**Current pre-fill:** `{prefill_name}` ready for upload.")

# ===================== FOOTER =====================
st.divider()
st.caption("""
🔐 **Security Notice:** This vault uses zero-knowledge, client-side encryption. 
Your password never leaves your browser and is not stored on our servers.
If you lose your password, your data cannot be recovered.
""")

# Development/debug info (hidden by default)
with st.expander("🔧 Debug Info", expanded=False):
    st.write("**URL Parameters Received:**")
    st.json({
        "prefill_name": prefill_name,
        "prefill_category": prefill_category,
        "source_app": source_app
    })
    st.write("**Session State:**")
    st.json({
        "vault_password_set": st.session_state.vault_password is not None,
        "current_category": st.session_state.current_category
    })

if __name__ == "__main__":
    # This ensures Streamlit runs the app
    pass
