import sqlite3
import csv
import json
import os

DEFAULT_DB_PATH = "nids_alerts.db"

def init_db(db_path=DEFAULT_DB_PATH):
    """Initializes the SQLite database and creates alerts table if not exists."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            description TEXT,
            raw_payload TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_alert(alert, db_path=DEFAULT_DB_PATH):
    """Inserts a new alert record into the SQLite database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (timestamp, severity, attack_type, rule_name, src_ip, dst_ip, description, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get('timestamp', ''),
            alert.get('severity', 'INFO'),
            alert.get('attack_type', 'UNKNOWN'),
            alert.get('rule_name', 'Default Rule'),
            alert.get('src_ip', '0.0.0.0'),
            alert.get('dst_ip', '0.0.0.0'),
            alert.get('description', ''),
            alert.get('raw_payload', '')
        ))
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id
    except Exception as e:
        print(f"Database Insert Error: {e}")
        return None

def fetch_alerts(db_path=DEFAULT_DB_PATH, ip_filter="", severity_filter="ALL", attack_filter="ALL"):
    """Fetches alert records matching optional search filters."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    query = "SELECT id, timestamp, severity, attack_type, rule_name, src_ip, dst_ip, description, raw_payload FROM alerts WHERE 1=1"
    params = []

    if ip_filter.strip():
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
        term = f"%{ip_filter.strip()}%"
        params.extend([term, term])

    if severity_filter and severity_filter != "ALL":
        query += " AND severity = ?"
        params.append(severity_filter)

    if attack_filter and attack_filter != "ALL":
        query += " AND attack_type = ?"
        params.append(attack_filter)

    query += " ORDER BY id DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "timestamp": r[1],
            "severity": r[2],
            "attack_type": r[3],
            "rule_name": r[4],
            "src_ip": r[5],
            "dst_ip": r[6],
            "description": r[7],
            "raw_payload": r[8]
        })
    return results

def clear_db(db_path=DEFAULT_DB_PATH):
    """Clears all records in the alerts database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()

def export_alerts_to_csv(filepath, db_path=DEFAULT_DB_PATH):
    """Exports all alerts to a CSV file."""
    alerts = fetch_alerts(db_path)
    if not alerts:
        return False, "No alerts to export."

    fieldnames = ["id", "timestamp", "severity", "attack_type", "rule_name", "src_ip", "dst_ip", "description"]
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(alerts)
        return True, f"Successfully exported {len(alerts)} alerts to CSV."
    except Exception as e:
        return False, f"Failed to export CSV: {e}"

def export_alerts_to_json(filepath, db_path=DEFAULT_DB_PATH):
    """Exports all alerts to a JSON file."""
    alerts = fetch_alerts(db_path)
    if not alerts:
        return False, "No alerts to export."

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, indent=2)
        return True, f"Successfully exported {len(alerts)} alerts to JSON."
    except Exception as e:
        return False, f"Failed to export JSON: {e}"
