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
    print("🛡️ Requesting Administrator privileges to access Network Card...")
    # Re-run the script with admin rights
    # 'runas' triggers the Windows UAC prompt
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()


# ==========================================================
# REST OF YOUR AUTOMATION CODE BELOW
# ==========================================================

def start_nids():
    print("Administrator access granted.")

    # 1. Start Sniffer (This will now inherit Admin rights)
    print("Launching Packet Sniffer...")
    subprocess.Popen(['start', 'cmd', '/k', 'python', 'scripts/sniffer.py'], shell=True)
    time.sleep(5)

    # 2. Start Spark Processor
    print("Launching Spark AI...")
    subprocess.Popen(['start', 'cmd', '/k', 'python', 'scripts/realtime_processor.py'], shell=True)
    time.sleep(15)

    # 3. Start Dashboard
    print("Opening Dashboard...")
    subprocess.run(['streamlit', 'run', 'scripts/dashboard.py'])


if __name__ == "__main__":
    start_nids()