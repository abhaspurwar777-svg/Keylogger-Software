from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from scanner import scan_processes
import psutil
import os

app = Flask(__name__)
CORS(app)

# Serve the frontend
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../frontend'))

@app.route('/')
def serve_index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(FRONTEND_DIR, path)

@app.route('/api/scan', methods=['GET'])
def run_scan():
    """
    API endpoint to initiate a process scan.
    Returns JSON containing process list and detection statistics.
    """
    try:
        results = scan_processes()
        return jsonify({
            "status": "success",
            "data": results
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/terminate/<int:pid>', methods=['POST'])
def terminate_process(pid):
    """
    API endpoint to terminate a specific process safely.
    """
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        # Actually attempt to terminate the process
        proc.terminate()
        return jsonify({"status": "success", "message": f"Successfully terminated {name} (PID: {pid})."})
    except psutil.NoSuchProcess:
        return jsonify({"status": "error", "message": "Process no longer exists or was already terminated."}), 404
    except psutil.AccessDenied:
        return jsonify({"status": "error", "message": "Access Denied. Administrator privileges are required to terminate this system process."}), 403
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    print(f"Starting Threat Analyzer backend... Serving frontend from {FRONTEND_DIR}")
    app.run(debug=True, port=5001)
