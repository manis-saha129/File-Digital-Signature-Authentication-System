import streamlit as st


# Function for the File Digital Signature Authentication page
def file_signature_page():
    import main  # App functionality for signing and key generation
    main.run()  # Assuming 'main.py' has a function `run()` for the main logic


# Function for the Document Authentication page
def document_authentication_page():
    import test  # Test functionality for document authentication and signature verification
    test.run()  # Assuming 'test.py' has a function `run()` for the main logic


# Navigation between pages
st.sidebar.title("Navigation")
page = st.sidebar.selectbox("Choose a page to view:", ["File Digital Signature Authentication", "Document Authentication"])

# Display content based on selected page
if page == "File Digital Signature Authentication":
    file_signature_page()
elif page == "Document Authentication":
    document_authentication_page()
