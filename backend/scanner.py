import psutil

# A mock list of "suspicious" process names/patterns that might indicate a keylogger or monitoring tool.
# In a real AV, this would be a large database of signatures and heuristics.
SUSPICIOUS_INDICATORS = [
    "keylog", "monitor", "hook", "capture", "stealth", "pynput_demo", "mock_threat"
]

SUSPICIOUS_PATHS = [
    "appdata\\local\\temp", "downloads", "public"
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
            
            # Check for suspicious execution paths
            exe_path = info.get('exe') or ""
            if exe_path and any(sp in exe_path.lower() for sp in SUSPICIOUS_PATHS):
                is_suspicious = True
                reason_msg = "Running from anomalous/temp directory"
            elif is_suspicious:
                reason_msg = "Matched heuristic keyword signature"
            else:
                reason_msg = ""
                
            # Advanced Heuristic: Network connection combined with suspicious traits
            has_network = False
            try:
                # Some processes may block connection info queries
                conns = proc.connections(kind='inet')
                if len(conns) > 0:
                    has_network = True
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
            if is_suspicious and has_network:
                reason_msg += " + Active network exfiltration socket"
            
            proc_data = {
                "pid": info.get('pid'),
                "name": name,
                "exe": exe_path or "Unknown",
                "username": info.get('username') or "Unknown",
                "is_suspicious": is_suspicious,
                "has_network": has_network,
                "reason": reason_msg
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
