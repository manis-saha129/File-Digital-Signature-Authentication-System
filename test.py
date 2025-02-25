import streamlit as st
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature


def run():
    # Set up the database folder for signature files
    SIGNATURES_FOLDER = "signatures_db"

    # Ensure the folder exists
    if not os.path.exists(SIGNATURES_FOLDER):
        os.makedirs(SIGNATURES_FOLDER)

    # Function to load a public key
    def load_public_key(public_key_pem):
        try:
            return serialization.load_pem_public_key(public_key_pem)
        except Exception:
            return None  # Return None if there is an error

    # Function to verify file with a given signature
    def verify_signature(file_data, signature, public_key_pem):
        try:
            public_key = load_public_key(public_key_pem)
            if public_key is None:
                return False, "Error loading public key"  # Return error message if key can't be loaded

            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True, ""  # Return True with empty message if signature matches
        except InvalidSignature:
            return False, ""  # Return False without message if signature doesn't match
        except Exception as e:
            return False, str(e)  # Return False with error message

    # Streamlit App
    st.title("Document Authentication System")

    st.header("Upload a Document for Authentication")
    uploaded_file = st.file_uploader("Upload your document", type=None)

    # Allow only one public key upload
    st.subheader("Upload Public Key")
    user_uploaded_key = st.file_uploader(
        "Upload the public key (.pem) to verify this document",
        type=["pem"],
        key="file_uploader_public_key"  # Unique key for public key uploader
    )

    # Document Authentication Logic
    if uploaded_file and user_uploaded_key:
        file_data = uploaded_file.read()
        public_key_pem = user_uploaded_key.read()

        # Load public key only once and check for errors
        public_key = load_public_key(public_key_pem)
        if public_key is None:
            st.error(
                "Error loading public key: Ensure the key is a valid public key with BEGIN PUBLIC KEY/END PUBLIC KEY delimiters.")
        else:
            # Loop through all signature files in the signatures_db folder
            signature_files = [f for f in os.listdir(SIGNATURES_FOLDER) if f.endswith('.sig')]
            matched_signatures = []

            for sig_file in signature_files:
                sig_path = os.path.join(SIGNATURES_FOLDER, sig_file)

                with open(sig_path, "rb") as sig_f:
                    signature = sig_f.read()

                # Verify signature with the provided public key
                is_verified, error_msg = verify_signature(file_data, signature, public_key_pem)
                if is_verified:
                    matched_signatures.append(sig_file)
                elif error_msg:
                    st.error(error_msg)  # Show error message if any

            if matched_signatures:
                st.success("File is authenticated!")
                st.write("Matched Signatures:")
                for sig in matched_signatures:
                    st.write(f"✔ {sig}")
            else:
                st.error("No matching signature found in the database.")
    else:
        st.warning("Please upload both the document and the public key.")

    # Optional: Manage Signature Files (Upload and Delete)
    st.sidebar.title("Manage Signatures")

    # Upload a new .sig file
    st.sidebar.subheader("Upload a Signature")
    uploaded_sig = st.sidebar.file_uploader("Upload a .sig file", type=["sig"])
    sig_name = st.sidebar.text_input("Enter name for the signature file (without extension)")

    if uploaded_sig and sig_name:
        sig_filename = f"{sig_name}.sig"
        sig_path = os.path.join(SIGNATURES_FOLDER, sig_filename)

        if os.path.exists(sig_path):
            st.sidebar.error("A signature with this name already exists. Choose a different name.")
        else:
            with open(sig_path, "wb") as f:
                f.write(uploaded_sig.read())
            st.sidebar.success(f"Signature '{sig_filename}' has been uploaded and stored.")

    # Delete an existing .sig file
    st.sidebar.subheader("Delete a Signature")
    stored_sigs = [f for f in os.listdir(SIGNATURES_FOLDER) if f.endswith('.sig')]

    if stored_sigs:
        sig_to_delete = st.sidebar.selectbox("Select a signature to delete", stored_sigs)
        if st.sidebar.button("Delete Selected Signature"):
            os.remove(os.path.join(SIGNATURES_FOLDER, sig_to_delete))
            st.sidebar.success(f"Signature '{sig_to_delete}' has been deleted.")
    else:
        st.sidebar.info("No signatures available to delete.")
