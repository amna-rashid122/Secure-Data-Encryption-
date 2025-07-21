

import streamlit as st
from cryptography.fernet import Fernet
import base64

# ---------- Session State Setup ----------
if "data_store" not in st.session_state:
    st.session_state.data_store = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# ---------- Helper Functions ----------
def generate_key(passkey: str) -> bytes:
    return base64.urlsafe_b64encode(passkey.ljust(32)[:32].encode())

def encrypt_data(data: str, key: bytes) -> str:
    return Fernet(key).encrypt(data.encode()).decode()

def decrypt_data(token: str, key: bytes) -> str:
    return Fernet(key).decrypt(token.encode()).decode()

def reset_auth():
    st.session_state.authorized = False
    st.session_state.failed_attempts = 0

# ---------- Auth Check ----------
if not st.session_state.authorized:
    st.warning("🔒 Reauthorization Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.authorized = True
            st.success("🔓 Access granted!")
        else:
            st.error("❌ Invalid credentials")

# ---------- Main App ----------
if st.session_state.authorized:
    st.title("🔐 Secure Data Vault")

    menu = st.sidebar.radio("Choose Action", ["Store Data", "Retrieve Data"])

    if menu == "Store Data":
        st.subheader("🔒 Store Data with a Passkey")
        key_input = st.text_input("Enter a unique passkey")
        user_data = st.text_area("Enter the data to encrypt")
        if st.button("Encrypt & Store"):
            if key_input and user_data:
                key = generate_key(key_input)
                encrypted = encrypt_data(user_data, key)
                st.session_state.data_store[key_input] = encrypted
                st.success("✅ Data encrypted and stored in memory.")
            else:
                st.warning("Please enter both passkey and data.")

    elif menu == "Retrieve Data":
        st.subheader("🔑 Retrieve Data")
        key_input = st.text_input("Enter your passkey to decrypt data")
        if st.button("Decrypt & Show"):
            if key_input in st.session_state.data_store:
                try:
                    key = generate_key(key_input)
                    decrypted = decrypt_data(st.session_state.data_store[key_input], key)
                    st.success("✅ Data retrieved successfully:")
                    st.code(decrypted)
                    st.session_state.failed_attempts = 0  # reset on success
                except Exception:
                    st.session_state.failed_attempts += 1
                    st.error("❌ Invalid passkey or corrupted data.")
            else:
                st.session_state.failed_attempts += 1
                st.error("❌ No data found with that passkey.")

        # Force reauthentication after 3 failures
        if st.session_state.failed_attempts >= 3:
            st.error("🔒 Too many failed attempts. Please log in again.")
            reset_auth()
