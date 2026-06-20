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

@app.route('/api/telemetry', methods=['GET'])
def get_telemetry():
    """
    API endpoint returning global system CPU and RAM usage.
    """
    return jsonify({
        "cpu": psutil.cpu_percent(interval=None),
        "ram": psutil.virtual_memory().percent
    })

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

@app.route('/<path:path>')
def serve_static(path):
    # This must be at the bottom to act as a catch-all for frontend assets
    return send_from_directory(FRONTEND_DIR, path)

if __name__ == "__main__":
    print(f"Starting Threat Analyzer backend... Serving frontend from {FRONTEND_DIR}")
    app.run(debug=True, port=5001)
