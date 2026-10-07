"""
Module 2: Integrity Verifier & Binary Extraction Engine
-------------------------------------------------------
Called by Module 1 (UI). Output is read by Module 3 (Regex) and Module 4 (ML/Risk).

Usage from Module 1:
    from module2_extractor import process_firmware
    result = process_firmware("/tmp/session_ab12/fw.bin", expected_hash=None)

Usage from terminal (for testing):
    python module2_extractor.py firmware.bin [--expected-hash <sha256>]
"""
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DISK_SPACE_FACTOR = 5          # extracted data is often 3-5x the original size
BINWALK_TIMEOUT = 600          # seconds

# Hints used to build "file-to-module mappings" in the manifest
CONFIG_EXT = {".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
              ".pem", ".key", ".crt", ".txt", ".properties"}
CONFIG_NAMES = {"passwd", "shadow", "group", "hosts", "inittab", "fstab"}
SCRIPT_EXT = {".sh", ".py", ".lua", ".pl", ".php", ".js", ".cgi"}
SCRIPT_DIR_HINTS = ("init.d", "rc.d", "rcS", "rc.local", "cron")


# ---------------------------------------------------------------- Stage 1
def sha256_file(path, chunk_size=1024 * 1024):
    """Compute SHA-256 in chunks so large firmware files don't fill RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def verify_integrity(fw_path, expected_hash=None):
    computed = sha256_file(fw_path)
    if not expected_hash:
        return {"computed_sha256": computed, "expected_sha256": None,
                "status": "NO_BASELINE",
                "message": "No vendor hash supplied; integrity could not be "
                           "verified (fingerprint recorded only)."}
    match = computed.lower() == expected_hash.strip().lower()
    return {"computed_sha256": computed, "expected_sha256": expected_hash.strip(),
            "status": "VERIFIED" if match else "MISMATCH",
            "message": "Hash matches vendor baseline." if match else
                       "HIGH SEVERITY: hash mismatch - possible tampering or "
                       "corruption. Processing halted."}


# ------------------------------------------------------------ Stages 2 & 3
def check_disk_space(fw_path, out_base):
    needed = os.path.getsize(fw_path) * DISK_SPACE_FACTOR
    free = shutil.disk_usage(out_base).free
    return free >= needed, needed, free


def run_binwalk(fw_path, out_dir):
    """Signature scan + recursive (matryoshka) extraction using Binwalk."""
    if shutil.which("binwalk") is None:
        return {"ok": False, "signatures": "",
                "errors": ["binwalk is not installed or not on PATH"]}
    cmd = ["binwalk", "-e", "-M", "-C", str(out_dir), str(fw_path)]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        cmd.insert(1, "--run-as=root")   # binwalk 2.x refuses to run as root otherwise
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=BINWALK_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"ok": False, "signatures": "",
                "errors": [f"binwalk timed out after {BINWALK_TIMEOUT}s"]}
    errors = [l for l in p.stderr.splitlines() if l.strip()]
    return {"ok": p.returncode == 0, "signatures": p.stdout, "errors": errors}


# ---------------------------------------------------------------- Stage 4
def sanitize_tree(root):
    """Remove dangerous symlinks, normalize permissions, build file inventory."""
    root = Path(root).resolve()
    symlinks, removed, files = [], [], []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        for name in list(dirnames) + filenames:
            p = dp / name
            if p.is_symlink():
                target = os.readlink(p)
                resolved = (dp / target).resolve() if not os.path.isabs(target) \
                    else Path(target)
                inside = str(resolved).startswith(str(root))
                symlinks.append({"path": str(p.relative_to(root)), "target": target,
                                 "inside_tree": inside})
                if not inside or not resolved.exists():
                    try:
                        p.unlink()
                        removed.append(str(p.relative_to(root)))
                    except OSError:
                        pass
                    if name in dirnames:
                        dirnames.remove(name)
                continue
            try:                                     # drop exec/setuid bits
                os.chmod(p, 0o755 if p.is_dir() else 0o644)
            except OSError:
                pass
            if p.is_file():
                files.append(p)
    return files, symlinks, removed, root


def classify(files, root):
    configs, scripts, other = [], [], []
    for f in files:
        rel = str(f.relative_to(root))
        ext = f.suffix.lower()
        if ext in SCRIPT_EXT or any(h in rel for h in SCRIPT_DIR_HINTS):
            scripts.append(rel)
        elif ext in CONFIG_EXT or f.name in CONFIG_NAMES:
            configs.append(rel)
        else:
            other.append(rel)
    return configs, scripts, other


# ---------------------------------------------------------------- Pipeline
def process_firmware(fw_path, expected_hash=None, base_dir=None, progress=None):
    """
    Main entry point. `progress` is an optional callback(str) so Module 1 can
    show live status. Returns the manifest dict (also saved as manifest.json).
    """
    log = progress or (lambda msg: None)
    fw_path = Path(fw_path)
    base_dir = Path(base_dir or tempfile.gettempdir())
    t0 = time.time()
    manifest = {"firmware_file": fw_path.name,
                "size_bytes": fw_path.stat().st_size if fw_path.exists() else 0,
                "status": "STARTED", "warnings": [], "errors": []}

    if not fw_path.is_file():
        manifest.update(status="FAILED", errors=[f"File not found: {fw_path}"])
        return manifest

    # Stage 1 - integrity
    log("Stage 1/5: calculating SHA-256...")
    integrity = verify_integrity(fw_path, expected_hash)
    manifest["integrity"] = integrity
    if integrity["status"] == "MISMATCH":
        manifest.update(status="HALTED_TAMPERED", extraction_root=None)
        manifest["errors"].append(integrity["message"])
        return manifest
    if integrity["status"] == "NO_BASELINE":
        manifest["warnings"].append(integrity["message"])

    # Disk space check
    out_dir = base_dir / f"firmware_extracted_{integrity['computed_sha256'][:16]}"
    ok, needed, free = check_disk_space(fw_path, base_dir)
    if not ok:
        manifest.update(status="FAILED")
        manifest["errors"].append(
            f"Insufficient disk space: need ~{needed//2**20} MB, have {free//2**20} MB")
        return manifest
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)

    # Stages 2 & 3 - signature scan + recursive extraction
    log("Stage 2-3/5: scanning signatures and extracting with Binwalk...")
    bw = run_binwalk(fw_path, out_dir)
    manifest["binwalk_signatures"] = bw["signatures"]
    manifest["warnings"].extend(bw["errors"])

    # Stage 4 - sanitize + map
    log("Stage 4/5: sanitizing and mapping file system...")
    files, symlinks, removed, root = sanitize_tree(out_dir)
    configs, scripts, other = classify(files, root)

    if not files:
        manifest["status"] = "NO_FILES_EXTRACTED"
        manifest["warnings"].append(
            "Unknown or unsupported format: no files extracted. "
            "Downstream modules have nothing to scan.")
    elif bw["errors"] or not bw["ok"]:
        manifest["status"] = "PARTIAL"
    else:
        manifest["status"] = "SUCCESS"

    manifest.update({
        "extraction_root": str(root),
        "counts": {"total_files": len(files), "config_files": len(configs),
                   "script_files": len(scripts), "other_files": len(other),
                   "symlinks_found": len(symlinks),
                   "symlinks_removed": len(removed)},
        "symlinks": symlinks,
        # Hand-off lists: Module 3 reads configs+scripts, Module 4 reads scripts
        "module3_targets": configs + scripts,
        "module4_targets": scripts,
        "other_files": other,
        "elapsed_seconds": round(time.time() - t0, 2),
    })

    # Stage 5 - write manifest next to extracted tree
    log("Stage 5/5: writing manifest and handing off...")
    manifest_path = out_dir / "manifest.json"
    manifest["manifest_path"] = str(manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Module 2: integrity + extraction")
    ap.add_argument("firmware")
    ap.add_argument("--expected-hash", default=None)
    args = ap.parse_args()
    res = process_firmware(args.firmware, args.expected_hash, progress=print)
    print(json.dumps({k: v for k, v in res.items()
                      if k not in ("binwalk_signatures", "symlinks",
                                   "module3_targets", "module4_targets",
                                   "other_files")}, indent=2))
    sys.exit(0 if res["status"] in ("SUCCESS", "PARTIAL") else 1)
