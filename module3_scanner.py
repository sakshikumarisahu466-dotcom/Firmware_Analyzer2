import os
import re


def scan_files(scan_path):
    results = []

    if not scan_path or not os.path.exists(scan_path):
        return {
            "status": "NO_FILES_TO_SCAN",
            "findings": []
        }

    for root, dirs, files in os.walk(scan_path):

        for file_name in files:

            file_path = os.path.join(root, file_name)

            # Scan text/config/script files
            if not file_name.lower().endswith(
                (".txt", ".conf", ".cfg", ".ini",
                 ".sh", ".py", ".js", ".json",
                 ".xml", ".yaml", ".yml")
            ):
                continue

            try:
                with open(
                    file_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as file:
                    content = file.read()

                findings = []

                # Hardcoded password
                if re.search(
                    r"(password|passwd|pwd)\s*[:=]",
                    content,
                    re.IGNORECASE
                ):
                    findings.append("Possible hardcoded password")

                # API key / secret
                if re.search(
                    r"(api[-]?key|secret[-]?key|access[_-]?key)\s*[:=]",
                    content,
                    re.IGNORECASE
                ):
                    findings.append("Possible API key or secret")

                # Private key
                if "PRIVATE KEY" in content:
                    findings.append("Possible private key")

                # Suspicious commands / possible backdoor
                if re.search(
                    r"\b(wget|curl|nc|netcat)\b",
                    content,
                    re.IGNORECASE
                ):
                    findings.append("Suspicious command found")

                if findings:
                    results.append({
                        "file": file_path,
                        "findings": findings
                    })

            except Exception as e:
                results.append({
                    "file": file_path,
                    "findings": [f"Could not scan file: {e}"]
                })

    return {
        "status": "SCAN_COMPLETED",
        "findings": results
    }


def create_module4_input(scan_result):
    """
    Sends Module 3 findings to Module 4.
    """

    output_file = os.path.join(
        "Module4_ML",
        "scanner_output.txt"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        for item in scan_result.get("findings", []):

            file_path = item.get("file", "")
            findings = item.get("findings", [])

            for finding in findings:
                file.write(
                    f"{file_path}: {finding}\n"
                )

    return output_file