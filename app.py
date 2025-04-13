import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# In-memory storage
stored_data = {}
failed_attempts = {}

# Hash the passkey with SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Generate Fernet key (should ideally be stored securely)
def generate_fernet_key():
    return Fernet.generate_key()

# Streamlit App
def main():
    st.title("🔐 Secure Data Encryption System")

    menu = ["Home", "Store Data", "Retrieve Data"]
    choice = st.sidebar.radio("Navigate", menu)

    if choice == "Home":
        st.markdown("Welcome to a secure encryption tool built with **Python + Streamlit**.")
    
    elif choice == "Store Data":
        st.subheader("🔒 Store Your Data Securely")
        user_id = st.text_input("Enter User ID")
        data = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Enter Passkey", type="password")

        if st.button("Encrypt and Save"):
            if user_id and data and passkey:
                key = generate_fernet_key()
                f = Fernet(key)
                encrypted_data = f.encrypt(data.encode())
                hashed_pass = hash_passkey(passkey)

                stored_data[user_id] = {
                    "encrypted_data": encrypted_data,
                    "hashed_pass": hashed_pass,
                    "key": key
                }
                failed_attempts[user_id] = 0
                st.success("✅ Data encrypted and stored successfully.")
            else:
                st.warning("Please fill in all fields.")

    elif choice == "Retrieve Data":
        st.subheader("🔓 Retrieve and Decrypt Your Data")
        user_id = st.text_input("Enter User ID")
        passkey = st.text_input("Enter Passkey", type="password")

        if st.button("Decrypt"):
            if user_id not in stored_data:
                st.error("❌ User ID not found.")
                return

            if failed_attempts.get(user_id, 0) >= 3:
                st.error("🚫 Too many failed attempts. Please reauthorize.")
                return

            hashed_input = hash_passkey(passkey)
            if hashed_input == stored_data[user_id]["hashed_pass"]:
                f = Fernet(stored_data[user_id]["key"])
                decrypted_data = f.decrypt(stored_data[user_id]["encrypted_data"]).decode()
                st.success(f"🔍 Decrypted Data: `{decrypted_data}`")
                failed_attempts[user_id] = 0  # Reset after success
            else:
                failed_attempts[user_id] = failed_attempts.get(user_id, 0) + 1
                attempts_left = 3 - failed_attempts[user_id]
                st.warning(f"❗Incorrect passkey. Attempts left: {attempts_left}")

if __name__ == "__main__":
    main()
