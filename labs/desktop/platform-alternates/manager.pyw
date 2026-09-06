import subprocess
import sys
import argparse

# Tray GUI Daemon Manager (manager.pyw)
# Suppresses terminal console popups during background execution on Windows

def start_daemon(think_depth: int):
    # configuring STARTUPINFO using dwFlags |= STARTF_USESHOWWINDOW
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    
    # launching with CREATE_NO_WINDOW
    CREATE_NO_WINDOW = 0x08000000
    
    cmd = ["luminet_daemon.exe"]
    
    # parses custom @think=N parameter depths to override thinking properties
    if think_depth is not None:
        cmd.append(f"@think={think_depth}")
        
    process = subprocess.Popen(
        cmd,
        startupinfo=startupinfo,
        creationflags=CREATE_NO_WINDOW
    )
    return process

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--think", type=int, help="Override thinking properties (@think=N)")
    args = parser.parse_args()
    
    start_daemon(args.think)
