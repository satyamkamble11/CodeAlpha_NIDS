import os
import sys
import subprocess
from flask import Flask, render_template, jsonify, request, send_file
from ids_engine import IDSEngine
from db import fetch_alerts, clear_db, export_alerts_to_csv, export_alerts_to_json

app = Flask(__name__)
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "nids_alerts.db"))
engine = IDSEngine(db_path=db_path)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def status():
    return jsonify({
        "is_monitoring": engine.is_running,
        "interfaces": ["Default Interface"],
        "packets_analyzed": engine.packet_count,
        "alert_count": engine.alert_count
    })

@app.route('/api/start', methods=['POST'])
def start_nids():
    data = request.json or {}
    iface = data.get('interface')
    success, msg = engine.start(interface=iface)
    return jsonify({"success": success, "message": msg})

@app.route('/api/stop', methods=['POST'])
def stop_nids():
    success, msg = engine.stop()
    return jsonify({"success": success, "message": msg})

@app.route('/api/simulate', methods=['POST'])
def run_simulation():
    data = request.json or {}
    attack = data.get('attack', 'all')
    subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "attack_sim.py"), "--attack", attack])
    return jsonify({"success": True, "message": f"Triggered attack simulation: {attack}"})

@app.route('/api/alerts')
def get_alerts():
    ip_filter = request.args.get('ip', '')
    sev_filter = request.args.get('severity', 'ALL')
    atk_filter = request.args.get('attack', 'ALL')
    
    alerts = fetch_alerts(db_path=db_path, ip_filter=ip_filter, severity_filter=sev_filter, attack_filter=atk_filter)
    
    high = sum(1 for a in alerts if a['severity'] == "HIGH")
    med = sum(1 for a in alerts if a['severity'] == "MEDIUM")
    low = sum(1 for a in alerts if a['severity'] == "LOW")

    return jsonify({
        "alerts": alerts[:100],
        "kpi": {
            "total": len(alerts),
            "high": high,
            "medium": med,
            "low": low
        }
    })

@app.route('/api/block', methods=['POST'])
def block_ip():
    data = request.json or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({"success": False, "message": "No IP specified"}), 400

    blocklist_path = os.path.join(os.path.dirname(__file__), "blocklist.txt")
    with open(blocklist_path, "a") as f:
        f.write(f"{ip} # Blocked via NIDS Web SOC\n")
    return jsonify({"success": True, "message": f"IP {ip} added to blocklist.txt!"})

@app.route('/api/export/csv')
def export_csv():
    filepath = os.path.abspath(os.path.join(os.path.dirname(__file__), "nids_export.csv"))
    ok, msg = export_alerts_to_csv(filepath, db_path=db_path)
    if ok:
        return send_file(filepath, as_attachment=True, download_name="nids_alerts.csv")
    return jsonify({"error": msg}), 400

@app.route('/api/export/json')
def export_json():
    filepath = os.path.abspath(os.path.join(os.path.dirname(__file__), "nids_export.json"))
    ok, msg = export_alerts_to_json(filepath, db_path=db_path)
    if ok:
        return send_file(filepath, as_attachment=True, download_name="nids_alerts.json")
    return jsonify({"error": msg}), 400

if __name__ == '__main__':
    print("🛡️ Launching NIDS SOC Web Dashboard on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
