import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import os


def run():
    # Cache to hold keys
    if 'private_key_pem' not in st.session_state:
        st.session_state.private_key_pem = None
        st.session_state.public_key_pem = None

    # Key Generation
    @st.cache_data
    def generate_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Serialize keys
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_key_pem, public_key_pem

    # Sign File
    def sign_file(file_data, private_key_pem):
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    # Verify File Signature with Error Management
    def verify_file_signature(file_data, signature, public_key_pem):
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except ValueError:
            st.error("Invalid public key format. Ensure the file contains valid BEGIN/END PUBLIC KEY delimiters.")
        except InvalidSignature:
            st.error("Signature verification failed. The signature does not match the file.")
        except Exception as e:
            st.error(f"Unexpected error: {str(e)}")
        return False

    # Streamlit GUI
    st.title("File Digital Signature Authentication System")

    st.header("Key Management")
    if st.button("Generate Keys"):
        private_key_pem, public_key_pem = generate_keys()
        st.session_state.private_key_pem = private_key_pem
        st.session_state.public_key_pem = public_key_pem
        st.success("Keys generated successfully!")

    # Display download buttons for keys if they exist
    if st.session_state.private_key_pem and st.session_state.public_key_pem:
        st.download_button(
            label="Download Private Key",
            data=st.session_state.private_key_pem,
            file_name="private_key.pem",
            mime="application/x-pem-file"
        )
        st.download_button(
            label="Download Public Key (recommended)",
            data=st.session_state.public_key_pem,
            file_name="public_key.pem",
            mime="application/x-pem-file"
        )
    else:
        st.warning("Keys not generated yet. Please generate keys to download.")

    st.header("File Signing and Verification")
    option = st.radio("Choose an action:", ("Sign File", "Verify File"))

    if option == "Sign File":
        uploaded_file = st.file_uploader("Upload File to Sign", type=None)
        if uploaded_file and st.button("Sign File"):
            if st.session_state.private_key_pem:
                signature = sign_file(uploaded_file.read(), st.session_state.private_key_pem)
                st.success("File signed successfully!")
                st.download_button(
                    label="Download Signature",
                    data=signature,
                    file_name=f"{uploaded_file.name}.sig",
                    mime="application/octet-stream"
                )
            else:
                st.error("Private key not found. Please generate keys first.")

    elif option == "Verify File":
        uploaded_file = st.file_uploader("Upload File to Verify", type=None)
        signature_file = st.file_uploader("Upload Signature File", type=["sig"])
        public_key_file = st.file_uploader("Upload Public Key", type=["pem"])

        if uploaded_file and signature_file and public_key_file and st.button("Verify File"):
            file_data = uploaded_file.read()
            signature = signature_file.read()
            public_key_pem = public_key_file.read()
            verification = verify_file_signature(file_data, signature, public_key_pem)
            if verification:
                st.success("Signature is valid. File is authentic.")
