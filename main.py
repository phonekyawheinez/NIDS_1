import sys
import ctypes
import os
import subprocess
import time


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    print("🛡️ Requesting Administrator privileges to access Network Interface...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()


# ==========================================================
# DOCKER ORCHESTRATION
# ==========================================================

def start_nids():
    print("✅ Administrator access granted.")

    # 1. Clean up old containers and logs
    print("🧹 Cleaning up old session...")
    # This is the PowerShell-safe way to clean folders
    subprocess.run(
        ["powershell", "Remove-Item -Path ./logs/zeek/*, ./logs/alerts/* -Force -ErrorAction SilentlyContinue"],
        shell=True)

    # 2. Start the NIDS via Docker Compose
    print("🚀 Launching NIDS (Zeek + Spark + Dashboard)...")
    print("This may take a minute if images need to be built...")

    # We use 'docker-compose up' which starts EVERYTHING in your .yml file
    # --build ensures any changes to your scripts are included
    try:
        subprocess.run(["docker-compose", "up", "--build"], check=True)
    except KeyboardInterrupt:
        print("\n🛑 Stopping NIDS...")
        subprocess.run(["docker-compose", "down"])
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    start_nids()