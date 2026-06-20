import psutil

# A mock list of "suspicious" process names/patterns that might indicate a keylogger or monitoring tool.
# In a real AV, this would be a large database of signatures and heuristics.
SUSPICIOUS_INDICATORS = [
    "keylog", "monitor", "hook", "capture", "stealth", "pynput_demo"
]

def scan_processes():
    """
    Enumerates all running processes on the system using psutil.
    Flags any processes that match our mock suspicious indicators.
    """
    scanned_results = {
        "total_processes": 0,
        "suspicious_found": 0,
        "processes": []
    }
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            scanned_results["total_processes"] += 1
            info = proc.info
            name = info.get('name') or ""
            
            # Simple mock heuristic: check if process name contains suspicious keywords
            is_suspicious = any(indicator in name.lower() for indicator in SUSPICIOUS_INDICATORS)
            
            # Additional dummy check for educational purposes:
            # We flag python.exe sometimes if we pretend it's running a suspicious script, 
            # but we'll stick to name matching for simplicity.
            
            proc_data = {
                "pid": info.get('pid'),
                "name": name,
                "exe": info.get('exe') or "Unknown",
                "username": info.get('username') or "Unknown",
                "is_suspicious": is_suspicious,
                "reason": "Matched heuristic keyword" if is_suspicious else ""
            }
            
            scanned_results["processes"].append(proc_data)
            
            if is_suspicious:
                scanned_results["suspicious_found"] += 1
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    # Sort processes: suspicious first, then by PID
    scanned_results["processes"].sort(key=lambda x: (not x["is_suspicious"], x["pid"]))
    
    return scanned_results

if __name__ == "__main__":
    # Test the scanner locally
    results = scan_processes()
    print(f"Scanned {results['total_processes']} processes.")
    print(f"Found {results['suspicious_found']} suspicious processes.")
