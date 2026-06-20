import time
import socket
import sys

def mock_keylogger():
    print("="*50)
    print("WARNING: MOCK THREAT SIMULATOR RUNNING")
    print("="*50)
    print("[*] Initiating memory hooks (simulated)...")
    time.sleep(1)
    
    print("[*] Establishing anomalous outbound socket connection...")
    try:
        # Bind a dummy socket to simulate network behavior
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        print(f"[*] Bound to port {s.getsockname()[1]} (Awaiting C2 instructions)")
    except Exception as e:
        print(f"[!] Failed to bind socket: {e}")
        
    print("\n[+] The mock threat is now active.")
    print("--> Go to the ThreatAnalyze Dashboard and 'INITIALIZE SCAN' to detect this process.")
    print("\nPress Ctrl+C to terminate the simulator.")
    
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Terminating mock threat simulator...")
        sys.exit(0)

if __name__ == "__main__":
    # Ensure process name reflects something we flag heuristically
    # (Since this runs as python.exe, the actual window title or process invocation might vary,
    #  but our scanner checks for 'mock_threat' in the command line or name)
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW("mock_threat_simulator")
    mock_keylogger()
