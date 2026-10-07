import streamlit as st
from module2_extractor import process_firmware
from module3_scanner import scan_files, create_module4_input
import tempfile
import subprocess
import sys
import os
st.title("IoT Firmware Security Analyzer")


st.write(
    "Automated Firmware Integrity Verification "
    "and Vulnerability Assessment Pipeline"
)

st.header("Upload Firmware")

uploaded_file = st.file_uploader(
    "Choose a firmware file",
    type=["bin"]
)

st.header("SHA-256 Hash")

hash_value = st.text_input(
    "Enter SHA-256 hash",
    placeholder="Enter firmware SHA-256 hash..."
)

if st.button("🔍 Analyze Firmware"):
    if uploaded_file is None:
        st.error("Please upload a firmware file.")
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as temp_file:
            temp_file.write(uploaded_file.getbuffer())
            firmware_path = temp_file.name

        result = process_firmware(
            firmware_path,
            expected_hash=hash_value if hash_value else None
        )
        scan_result = scan_files(
            result.get("extraction_root")
        )

        create_module4_input(scan_result)
        subprocess.run([sys.executable,"ml_classifier.py"],check=False)

        st.subheader("Module 3 Result")
        st.write("Status:", scan_result["status"])
        st.write("Findings:", scan_result["findings"])
        st.subheader("Module 4 Result")

        if os.path.exists("Module4_ML/results.csv"):
            with open("Module4_ML/results.csv", "r", encoding="utf-8") as file:
                module4_result = file.read()

            st.text(module4_result)
        st.subheader("Module 2 Result")
        st.write("Status:", result["status"])

        if "integrity" in result:
            st.write("SHA-256:", result["integrity"]["computed_sha256"])

        if result.get("errors"):
            st.error(result["errors"])

        if result.get("warnings"):
            st.warning(result["warnings"])

        if result.get("extraction_root"):
            st.success("Firmware extraction completed.")
            st.write("Extracted files:", result["counts"]["total_files"])