import streamlit as st
import hashlib
import uuid
import base64
import time
import os
import json
from datetime import datetime

# -------------------- Session Initialization --------------------
def init_session():
    default_values = {
        'encryption_key': os.urandom(16).hex(),
        'stored_data': {},
        'failed_attempts': 0,
        'locked_until': 0,
        'current_data_id': None
    }
    for key, value in default_values.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session()

# -------------------- Utility Functions --------------------

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def simple_encrypt(text, key):
    key_bytes = (key.encode() * (len(text) // len(key) + 1))[:len(text)]
    encrypted_bytes = bytes([ord(c) ^ k for c, k in zip(text, key_bytes)])
    return base64.b64encode(encrypted_bytes).decode()

def simple_decrypt(encrypted_text, key):
    try:
        encrypted_bytes = base64.b64decode(encrypted_text)
        key_bytes = (key.encode() * (len(encrypted_bytes) // len(key) + 1))[:len(encrypted_bytes)]
        return ''.join([chr(b ^ k) for b, k in zip(encrypted_bytes, key_bytes)])
    except Exception:
        return None

def encrypt_data(text, passkey):
    combined_key = passkey + st.session_state.encryption_key
    return simple_encrypt(text, combined_key)

def decrypt_data(encrypted_text, passkey):
    try:
        data_id = st.session_state.current_data_id
        if data_id not in st.session_state.stored_data:
            return None

        data_entry = st.session_state.stored_data[data_id]
        if data_entry["passkey"] == hash_passkey(passkey):
            st.session_state.failed_attempts = 0
            combined_key = passkey + st.session_state.encryption_key
            return simple_decrypt(encrypted_text, combined_key)
        else:
            st.session_state.failed_attempts += 1
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        return None

# -------------------- UI Components --------------------

st.title("🔒 Secure Data Encryption System")

# Lockout check
current_time = time.time()
if st.session_state.locked_until > current_time:
    wait_time = int(st.session_state.locked_until - current_time)
    st.error(f"🔐 Too many failed attempts. Try again in {wait_time} seconds.")
    st.stop()

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

# -------------------- Home --------------------
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Use this app to **securely store and retrieve data** with passkeys.")

    if st.session_state.stored_data:
        st.subheader("Stored Data IDs")
        for data_id, entry in st.session_state.stored_data.items():
            created_at = entry.get("created_at", "Unknown")
            st.code(f"ID: {data_id} (Created: {created_at})", language="text")
    else:
        st.info("No data stored yet. Visit the 'Store Data' page to get started.")

# -------------------- Store Data --------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            data_id = str(uuid.uuid4())
            encrypted = encrypt_data(user_data, passkey)
            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted,
                "passkey": hash_passkey(passkey),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            st.success("✅ Data stored successfully!")
            st.info(f"Data ID: `{data_id}` — Save this to retrieve your data later.")
        else:
            st.error("⚠️ Please enter both data and passkey.")

# -------------------- Retrieve Data --------------------
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")

    if st.session_state.failed_attempts > 0:
        st.warning(f"Failed attempts: {st.session_state.failed_attempts}/3")

    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                st.session_state.current_data_id = data_id
                encrypted = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted = decrypt_data(encrypted, passkey)

                if decrypted:
                    st.success("✅ Decryption successful!")
                    st.code(decrypted, language="text")
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.locked_until = time.time() + 30
                        st.warning("🔐 Locked for 30 seconds. Reauthorization required.")
                        st.rerun()
            else:
                st.error("❌ Invalid Data ID.")
        else:
            st.error("⚠️ Please fill in both fields.")

# -------------------- Login --------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorize Access")
    st.write("Please reauthorize after multiple failed attempts.")

    master_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":  # For demo only
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            st.info("Redirecting to Retrieve Data...")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Incorrect master password.")

# -------------------- Sidebar Info --------------------
with st.sidebar:
    st.subheader("ℹ️ About")
    st.write("Securely store and retrieve data using encryption and unique passkeys.")

    st.markdown("---")
    st.subheader("System Status")
    st.write(f"🔐 Stored entries: {len(st.session_state.stored_data)}")
    if st.session_state.failed_attempts:
        st.write(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")
