import streamlit as st
import json
import os
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# Constants
KEY_FILE = "encryption.key"
DATA_FILE = "data.json"

# Get or generate encryption key
def get_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

# Hash passkey using PBKDF2
def hash_password_pbkdf2(passkey):
    return pbkdf2_hmac('sha256', passkey.encode(), b'salt', 100000).hex()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data if passkey matches
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_password_pbkdf2(passkey)
    for user, data in stored_data.items():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# Load user data from JSON
def load_data():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save user data to JSON
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Lockout checker
def check_lockout():
    if st.session_state.failed_attempts >= 3:
        remaining_time = max(0, 60 - int(time.time() - st.session_state.lockout_time))
        if remaining_time > 0:
            st.error(f"Too many failed attempts. Please wait {remaining_time} seconds.")
            return False
        else:
            st.session_state.failed_attempts = 0
            return True
    return True

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "username" not in st.session_state:
    st.session_state.username = None
if "login_success" not in st.session_state:
    st.session_state.login_success = False

# Load data and key
stored_data = load_data()
KEY = get_encryption_key()
cipher = Fernet(KEY)

# Streamlit App
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app allows you to securely store and retrieve your sensitive data using encryption.")

# Store Data Page
elif choice == "Store Data":
    if st.session_state.username and st.session_state.login_success:
        st.subheader("🔐 Store Encrypted Data")
        user_data = st.text_area("Enter your data:")
        passkey = st.text_input("Enter a secure passkey:", type="password")

        if st.button("Encrypt and Save"):
            if user_data and passkey:
                hashed_passkey = hash_password_pbkdf2(passkey)
                encrypted_text = encrypt_data(user_data)

                stored_data[st.session_state.username] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }

                save_data(stored_data)
                st.success("Your data has been securely stored!")
                st.text_area("Encrypted Output", value=encrypted_text, height=150)
            else:
                st.error("Both fields are required.")
    else:
        st.error("You must log in to store data.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if st.session_state.username:
        st.subheader("🔍 Retrieve Encrypted Data")
        default_encrypted = stored_data.get(st.session_state.username, {}).get("encrypted_text", "")
        encrypted_text = st.text_area("Your Encrypted Data:", value=default_encrypted, height=150)
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                if check_lockout():
                    decrypted = decrypt_data(encrypted_text, passkey)
                    if decrypted:
                        st.success(f"Decrypted Data: {decrypted}")
                    else:
                        st.error(f"Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
                else:
                    st.error("Please wait before trying again.")
            else:
                st.error("Both fields are required.")
    else:
        st.error("You must be logged in to retrieve your data.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        # Dummy credentials (replace with your own logic)
        if username == "user1" and hash_password_pbkdf2(password) == hash_password_pbkdf2("password123"):
            st.session_state.username = username
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = 0
            st.session_state.login_success = True
            st.success("Login successful!")
        else:
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time()
            st.error("Invalid username or password.")
