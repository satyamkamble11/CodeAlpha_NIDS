import threading
import queue
import time
import datetime
import os
import sys
from scapy.all import sniff, get_if_list
from rules import RuleEngine
from db import insert_alert, init_db

# Reuse packet parser logic
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "CodeAlpha_NetworkSniffer")))
try:
    from parser import parse_packet
except ImportError:
    # Fallback inline parse logic if path is different
    from scapy.all import IP, TCP, UDP, ICMP, Raw
    def parse_packet(packet, pkt_num=0):
        src_ip = packet[IP].src if IP in packet else "Unknown"
        dst_ip = packet[IP].dst if IP in packet else "Unknown"
        proto = "TCP" if TCP in packet else ("UDP" if UDP in packet else ("ICMP" if ICMP in packet else "Other"))
        raw_bytes = bytes(packet[Raw].load) if Raw in packet else b""
        ascii_payload = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)
        hex_dump = " ".join(f"{b:02X}" for b in raw_bytes)
        return {
            "no": pkt_num,
            "src": src_ip,
            "dst": dst_ip,
            "protocol": proto,
            "length": len(packet),
            "info": f"Port {packet[TCP].dport}" if TCP in packet else "",
            "src_port": packet[TCP].sport if TCP in packet else None,
            "dst_port": packet[TCP].dport if TCP in packet else None,
            "ascii_payload": ascii_payload,
            "hex_dump": hex_dump,
            "raw_payload": raw_bytes
        }

class IDSEngine:
    """
    Core Network Intrusion Detection Engine.
    Sniffs live network traffic, passes parsed packets to RuleEngine, logs alerts to SQLite,
    and streams real-time notifications to GUI queues.
    """
    def __init__(self, alert_queue=None, packet_queue=None, db_path="nids_alerts.db"):
        self.alert_queue = alert_queue if alert_queue is not None else queue.Queue()
        self.packet_queue = packet_queue if packet_queue is not None else queue.Queue()
        self.db_path = db_path
        self.rule_engine = RuleEngine()
        
        self.is_running = False
        self._sniff_thread = None
        self.packet_count = 0
        self.alert_count = 0
        self.selected_interface = None

        init_db(self.db_path)

    def _packet_handler(self, pkt):
        if not self.is_running:
            return

        self.packet_count += 1
        parsed = parse_packet(pkt, pkt_num=self.packet_count)
        self.packet_queue.put(parsed)

        # Evaluate signature rules
        alerts = self.rule_engine.evaluate_packet(parsed)
        for alert in alerts:
            self.alert_count += 1
            alert['id'] = self.alert_count
            alert['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Persist to SQLite
            insert_alert(alert, db_path=self.db_path)
            
            # Stream to GUI
            self.alert_queue.put(alert)

    def _run_sniff(self):
        kwargs = {
            "prn": self._packet_handler,
            "store": False,
            "stop_filter": lambda x: not self.is_running
        }
        if self.selected_interface and self.selected_interface != "Default Interface":
            kwargs["iface"] = self.selected_interface

        try:
            sniff(**kwargs)
        except Exception as e:
            err_alert = {
                "id": -1,
                "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "severity": "HIGH",
                "attack_type": "SYSTEM_ERROR",
                "rule_name": "NIDS Sniffer Fault",
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "description": f"Sniffer thread crashed: {e}",
                "raw_payload": ""
            }
            self.alert_queue.put(err_alert)
        finally:
            self.is_running = False

    def start(self, interface=None):
        if self.is_running:
            return False, "NIDS Engine is already monitoring."

        self.is_running = True
        self.selected_interface = interface
        self._sniff_thread = threading.Thread(target=self._run_sniff, daemon=True)
        self._sniff_thread.start()
        return True, "NIDS Monitoring Started."

    def stop(self):
        self.is_running = False
        return True, "NIDS Monitoring Stopped."
