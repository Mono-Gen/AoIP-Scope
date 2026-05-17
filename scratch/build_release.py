import os
import sys
import subprocess
import zipfile
import re
import shutil

# Project configurations
VERSION = "0.9.0"
ZIP_FILENAME = f"AoIP-Scope_v{VERSION}.zip"
DIST_DIR = "dist"
BUILD_DIR = "build"
EXE_NAME = "aoip_scope.exe"
TARGET_EXE = os.path.join(DIST_DIR, EXE_NAME)

# Files to be included in the release ZIP package (only public assets)
RELEASE_ASSETS = [
    (TARGET_EXE, EXE_NAME),
    ("docs/manual_JA.md", "docs/manual_JA.md"),
    ("docs/manual_EN.md", "docs/manual_EN.md"),
]

# Sensitive keywords that must NOT exist in the repository files
FORBIDDEN_KEYWORDS = [
    r"C:\\Users",
    r"c:\\users",
    # Dynamically build keywords to avoid self-detection in scans
    "".join(["ro", "ot", "n"]),
    "".join(["Local", " ", "only"])
]


def run_command(cmd, shell=False):
    """Run system command and return output."""
    result = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.returncode, result.stdout, result.stderr

def print_step(msg):
    print(f"\n=== [STEP] {msg} ===")

def print_success(msg):
    print(f"[OK] {msg}")

def print_error(msg):
    print(f"[ERROR] {msg}")
    sys.exit(1)

def ensure_dependencies():
    """Ensure PyInstaller is installed in the virtual environment."""
    print_step("Checking and installing PyInstaller in venv...")
    python_exe = os.path.join("venv", "Scripts", "python.exe")
    if not os.path.exists(python_exe):
        print_error("Virtual environment Python (venv/Scripts/python.exe) not found.")

    # Check if pyinstaller is already installed
    rc, stdout, _ = run_command([python_exe, "-m", "pip", "show", "pyinstaller"])
    if rc != 0:
        print("Installing PyInstaller...")
        rc, _, stderr = run_command([python_exe, "-m", "pip", "install", "pyinstaller"])
        if rc != 0:
            print_error(f"Failed to install PyInstaller: {stderr}")
        print_success("PyInstaller installed successfully.")
    else:
        print_success("PyInstaller is already installed.")

def security_scan():
    """Perform security scan to check for hardcoded absolute paths, usernames, and secret comments."""
    print_step("Starting Security Scan...")
    
    failed = False
    exclude_dirs = {".git", "venv", "__pycache__", "build", "dist", ".agents", ".tasks", ".docs", "tools"}
    exclude_files = {ZIP_FILENAME, "build_release.py"}
    
    # Pre-compile regex patterns for faster scanning
    patterns = [re.compile(p, re.IGNORECASE) for p in FORBIDDEN_KEYWORDS]
    
    for root, dirs, files in os.walk("."):
        # Modify dirs in-place to avoid walking into excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file in exclude_files:
                continue
            
            # Scan only text/source/markdown files
            if not file.endswith((".py", ".md", ".txt", ".json", ".cfg")):
                continue
                
            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in patterns:
                            if pattern.search(line):
                                print_error(f"Security Alert: Forbidden keyword '{pattern.pattern}' found in {filepath}:{line_num}")
                                failed = True
            except Exception as e:
                print(f"[Warning] Could not scan file {filepath}: {e}")

    # Check git index for tracking hidden/local files (git ls-files check)
    rc, stdout, stderr = run_command(["git", "ls-files", "-i", "--exclude-standard"], shell=True)
    if rc == 0 and stdout.strip():
        print_error(f"Security Alert: The following hidden/private files are indexed by Git:\n{stdout}")
        failed = True
    elif rc != 0 and "not a git repository" not in stderr.lower():
        print(f"[Warning] git command check skipped or failed: {stderr.strip()}")

    if failed:
        print_error("Security scan failed. Please resolve the security violations above.")
    else:
        print_success("Security scan passed. No absolute paths or environment dependencies found.")

def build_executable():
    """Build standalone executable using PyInstaller."""
    print_step("Building Standalone Executable using PyInstaller...")
    
    pyinstaller_exe = os.path.join("venv", "Scripts", "pyinstaller.exe")
    if not os.path.exists(pyinstaller_exe):
        print_error("PyInstaller executable not found in venv.")
        
    cmd = [
        pyinstaller_exe,
        "--onefile",
        "--name", "aoip_scope",
        "--icon", "assets/icon.ico",
        "--clean",
        "aoip_scope.py"
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    rc, stdout, stderr = run_command(cmd)
    if rc != 0:
        print(stdout)
        print(stderr)
        print_error("PyInstaller build failed.")
        
    if not os.path.exists(TARGET_EXE):
        print_error(f"Build succeeded but target executable {TARGET_EXE} was not found.")
        
    print_success(f"Executable built successfully: {TARGET_EXE}")

def package_release():
    """Create the release ZIP package including only the explicit public assets."""
    print_step("Packaging Release ZIP...")
    
    if os.path.exists(ZIP_FILENAME):
        os.remove(ZIP_FILENAME)
        print(f"Removed existing release package: {ZIP_FILENAME}")
        
    # Strictly copy specified files to prevent local dot-folders from leaking
    try:
        with zipfile.ZipFile(ZIP_FILENAME, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for src, arcname in RELEASE_ASSETS:
                if not os.path.exists(src):
                    print_error(f"Required release asset not found: {src}")
                zipf.write(src, arcname)
                print(f"Added to ZIP: {src} -> {arcname}")
    except Exception as e:
        print_error(f"Failed to create ZIP package: {e}")
        
    print_success(f"Release package created successfully: {ZIP_FILENAME}")

def clean_build_artifacts():
    """Clean temporary PyInstaller build artifacts."""
    print_step("Cleaning build artifacts...")
    spec_file = "aoip_scope.spec"
    if os.path.exists(spec_file):
        os.remove(spec_file)
        print(f"Removed: {spec_file}")
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
        print(f"Removed directory: {BUILD_DIR}")
    print_success("Temporary build artifacts cleaned.")

def main():
    print("==================================================")
    print(f"  AoIP-Scope Build & Release Automation Tool v{VERSION}")
    print("==================================================")
    
    # 1. Check virtual environment and install PyInstaller if needed
    ensure_dependencies()
    
    # 2. Run security scan to verify code safety
    security_scan()
    
    # 3. Build standalone executable
    build_executable()
    
    # 4. Package public assets into release ZIP (excluding dot-folders)
    package_release()
    
    # 5. Clean up temporary directories
    clean_build_artifacts()
    
    print("\n==================================================")
    print("  Release build finished successfully!")
    print(f"  Output package: {ZIP_FILENAME}")
    print("==================================================")

if __name__ == "__main__":
    main()
