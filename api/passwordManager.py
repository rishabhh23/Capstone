import streamlit as st
from cryptography.fernet import Fernet
import json
import os
from datetime import datetime

# Key management
def load_or_create_key():
    if "encryption_key" not in st.session_state:
        if os.path.exists("secret.key"):
            with open("secret.key", "rb") as key_file:
                st.session_state.encryption_key = key_file.read()
        else:
            st.session_state.encryption_key = Fernet.generate_key()
            with open("secret.key", "wb") as key_file:
                key_file.write(st.session_state.encryption_key)
    return Fernet(st.session_state.encryption_key)

# Core functionality
def password_manager():
    cipher = load_or_create_key()
    
    if "passwords" not in st.session_state:
        st.session_state.passwords = {}

    with st.expander("🔑 Password Vault", expanded=True):
        tab1, tab2 = st.tabs(["Add Entry", "View Passwords"])
        
        with tab1:
            service = st.text_input("Service/Website")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            if st.button("💾 Save"):
                encrypted = cipher.encrypt(password.encode()).decode()
                entry = {
                    "username": username,
                    "password": encrypted,
                    "timestamp": datetime.now().isoformat()
                }
                if service not in st.session_state.passwords:
                    st.session_state.passwords[service] = []
                st.session_state.passwords[service].append(entry)
                st.success("Saved!")

        with tab2:
            for service, entries in st.session_state.passwords.items():
                st.markdown(f"### 🔐 {service}")
                for i, data in enumerate(entries):
                    with st.container(border=True):
                        st.text(f"User: {data['username']}")
                        decrypted = cipher.decrypt(data['password'].encode()).decode()
                        st.text_input("Password", value=decrypted, type="password", key=f"pw_{service}_{i}")
                        if st.button("❌ Delete", key=f"del_{service}_{i}"):
                            st.session_state.passwords[service].pop(i)
                            if not st.session_state.passwords[service]:
                                del st.session_state.passwords[service]
                            st.rerun()
