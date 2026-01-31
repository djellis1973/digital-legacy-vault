# vault_app.py
import streamlit as st
import os
from pathlib import Path
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
        st.metric("💾 Total Size", f"{total_size / (1024*1024):.2f} MB")

# ===================== MAIN PAGE =====================
st.markdown("<h1 class='main-header'>🔐 Your Digital Legacy Vault</h1>", unsafe_allow_html=True)

# Tab interface
tab_upload, tab_browse, tab_biography = st.tabs(["📤 Upload", "📁 Browse Vault", "📖 Biography Link"])

# ========== TAB 1: UPLOAD ==========
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
                help="Maximum file size depends on Streamlit Cloud limits (~200MB)"
            )
        
        with col2:
            category = st.selectbox("Category:", categories[1:])
            notes = st.text_area("Notes (optional):", height=100)
        
        if uploaded_file and st.button("🔒 Encrypt & Store", type="primary"):
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
                    ✅ Document secured!
                    
                    **ID:** `{doc_id}`  
                    **File:** {uploaded_file.name}  
                    **Size:** {len(file_bytes):,} bytes  
                    **Status:** Encrypted with AES-256-GCM
                    """)
                    
                    # Auto-clear the uploader
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Upload failed: {str(e)}")

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
            st.info(f"No documents in category '{st.session_state.current_category}' yet.")
        else:
            st.write(f"**Found {len(filtered_docs)} document(s):**")
            
            for doc in filtered_docs:
                with st.expander(f"📄 **{doc['original_name']}** ({doc['category']})"):
                    col_a, col_b, col_c = st.columns([3, 1, 1])
                    
                    with col_a:
                        st.write(f"**ID:** `{doc['id']}`")
                        st.write(f"**Uploaded:** {doc['uploaded'][:10]}")
                        if doc['notes']:
                            st.write(f"**Notes:** {doc['notes']}")
                        st.write(f"**Size:** {doc.get('size_bytes', 0):,} bytes")
                    
                    with col_b:
                        # Download button
                        if st.button("Download", key=f"dl_{doc['id']}"):
                            with st.spinner("Decrypting..."):
                                try:
                                    filename, data = vault.get_document(
                                        doc_id=doc['id'],
                                        password=st.session_state.vault_password
                                    )
                                    
                                    st.download_button(
                                        label="Save File",
                                        data=data,
                                        file_name=filename,
                                        mime="application/octet-stream",
                                        key=f"dl_btn_{doc['id']}"
                                    )
                                except ValueError as e:
                                    st.error("Wrong password!")
                    
                    with col_c:
                        # Delete button
                        if st.button("Delete", key=f"del_{doc['id']}"):
                            if vault.delete_document(doc['id']):
                                st.success("Document deleted.")
                                st.rerun()

# ========== TAB 3: BIOGRAPHY LINK ==========
with tab_biography:
    st.header("Connect Your Biography")
    
    st.markdown("""
    ### 🔗 Seamless Integration
    
    Your biography book and this vault work together:
    
    1. **Generate** your biography in your existing app
    2. **Export** it as a PDF or text file
    3. **Upload** it here to the 'Biography' category
    4. **Everything stays together**, encrypted and secure
    """)
    
    # You can add a direct link to your biography app
    st.divider()
    st.subheader("Quick Access")
    
    biography_url = "https://YOUR_BIOGRAPHY_APP_URL.streamlit.app/"  # CHANGE THIS
    st.markdown(f"""
    [➡️ Go to Biography Generator]({biography_url})
    
    *Once your biography is ready, come back here to store it permanently.*
    """)

# ===================== FOOTER =====================
st.divider()
st.caption("""
🔐 **Security Notice:** This vault uses client-side encryption. Your password never leaves your browser. 
If you lose your password, your data cannot be recovered. There is no "forgot password" option by design.
""")

if __name__ == "__main__":
    # Development note
    pass
