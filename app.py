import streamlit as st
import hashlib
import uuid
import base64
import time
import os
import json
from datetime import datetime

# Initialize session state variables if they don't exist
if 'encryption_key' not in st.session_state:
    # Generate a random encryption key
    st.session_state.encryption_key = os.urandom(16).hex()
    
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
    
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
    
if 'locked_until' not in st.session_state:
    st.session_state.locked_until = 0
    
if 'current_data_id' not in st.session_state:
    st.session_state.current_data_id = None

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Simple XOR-based encryption (Caesar cipher with key)
def simple_encrypt(text, key):
    # Convert key to a repeating byte sequence
    key_bytes = key.encode() * (len(text) // len(key) + 1)
    key_bytes = key_bytes[:len(text)]
    
    # XOR each byte of text with corresponding byte of key
    encrypted_bytes = bytes([ord(text[i]) ^ key_bytes[i] for i in range(len(text))])
    
    # Convert to base64 for safe storage
    return base64.b64encode(encrypted_bytes).decode()

# Simple XOR-based decryption
def simple_decrypt(encrypted_text, key):
    try:
        # Convert from base64
        encrypted_bytes = base64.b64decode(encrypted_text)
        
        # Convert key to a repeating byte sequence
        key_bytes = key.encode() * (len(encrypted_bytes) // len(key) + 1)
        key_bytes = key_bytes[:len(encrypted_bytes)]
        
        # XOR each byte to decrypt
        decrypted_text = ''.join([chr(encrypted_bytes[i] ^ key_bytes[i]) for i in range(len(encrypted_bytes))])
        
        return decrypted_text
    except Exception:
        return None

# Function to encrypt data
def encrypt_data(text, passkey):
    # Use the passkey and our secret key for encryption
    encryption_key = passkey + st.session_state.encryption_key
    return simple_encrypt(text, encryption_key)

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        data_id = st.session_state.current_data_id
        if data_id in st.session_state.stored_data:
            data_entry = st.session_state.stored_data[data_id]
            hashed_passkey = hash_passkey(passkey)
            
            if data_entry["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                # Use the passkey and our secret key for decryption
                encryption_key = passkey + st.session_state.encryption_key
                return simple_decrypt(encrypted_text, encryption_key)
            else:
                st.session_state.failed_attempts += 1
                return None
        return None
    except Exception as e:
        st.session_state.failed_attempts += 1
        return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Check if system is locked
current_time = time.time()
if st.session_state.locked_until > current_time:
    remaining_time = int(st.session_state.locked_until - current_time)
    st.error(f"🔒 System locked due to too many failed attempts. Try again in {remaining_time} seconds.")
    st.stop()

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    # Display stored data IDs (not the content)
    if st.session_state.stored_data:
        st.subheader("Your Stored Data IDs")
        for data_id in st.session_state.stored_data:
            created_at = st.session_state.stored_data[data_id].get("created_at", "Unknown")
            st.code(f"ID: {data_id} (Created: {created_at})", language="text")
    else:
        st.info("No data stored yet. Go to the 'Store Data' page to add some!")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            # Generate a unique ID for this data
            data_id = str(uuid.uuid4())
            
            # Hash the passkey
            hashed_passkey = hash_passkey(passkey)
            
            # Encrypt the data
            encrypted_text = encrypt_data(user_data, passkey)
            
            # Store the data with timestamp
            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            st.success("✅ Data stored securely!")
            st.info(f"Your Data ID: {data_id}")
            st.warning("⚠️ Please save this ID to retrieve your data later!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    # Display number of failed attempts
    if st.session_state.failed_attempts > 0:
        st.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")
    
    data_id = st.text_input("Enter Your Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                st.session_state.current_data_id = data_id
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey)

                if decrypted_text:
                    st.success("✅ Decryption successful!")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")

                    if st.session_state.failed_attempts >= 3:
                        # Lock the system for 30 seconds
                        st.session_state.locked_until = time.time() + 30
                        st.warning("🔒 Too many failed attempts! System locked for 30 seconds.")
                        st.warning("Redirecting to Login Page for reauthorization.")
                        st.session_state.current_page = "Login"
                        st.experimental_rerun()
            else:
                st.error("❌ Data ID not found!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    st.write("You need to reauthorize after too many failed attempts.")
    
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        # For demonstration purposes, using a simple master password
        # In a real application, this should be more secure
        if login_pass == "admin123":  # Hardcoded for demo
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            st.info("Redirecting to Retrieve Data...")
            time.sleep(1)  # Short delay for user to see the message
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")

# Display app info in sidebar
with st.sidebar:
    st.subheader("About")
    st.write("This is a secure data encryption system that allows you to store and retrieve data using unique passkeys.")
    st.write("Your data is encrypted and can only be accessed with the correct passkey.")
    
    # Add a divider
    st.markdown("---")
    
    # Display system status
    st.subheader("System Status")
    st.write(f"🔐 Stored data entries: {len(st.session_state.stored_data)}")
    
    if st.session_state.failed_attempts > 0:
        st.write(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")