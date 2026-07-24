import os
import time
from collections import defaultdict, deque

class RuleEngine:
    """
    NIDS Signature and Threshold Rule Engine.
    Evaluates streaming network packets against predefined security detection rules.
    """
    def __init__(self, whitelist_file="whitelist.txt"):
        self.whitelist_file = whitelist_file
        self.whitelist = set()
        self.load_whitelist()

        # Sliding window state trackers
        # Format: { ip: deque([timestamp1, timestamp2, ...]) }
        self.syn_tracker = defaultdict(deque)        # Port Scan tracker
        self.icmp_tracker = defaultdict(deque)       # Ping Flood tracker
        self.ssh_tracker = defaultdict(deque)        # SSH Brute Force tracker
        self.ip_mac_table = {}                       # ARP Spoofing tracker { ip: mac }

    def load_whitelist(self):
        """Loads trusted IP addresses from whitelist.txt to minimize false positives."""
        self.whitelist = {"127.0.0.1", "localhost", "0.0.0.0"}
        if os.path.exists(self.whitelist_file):
            try:
                with open(self.whitelist_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.whitelist.add(line)
            except Exception as e:
                print(f"Error loading whitelist: {e}")

    def is_whitelisted(self, ip_address):
        return ip_address in self.whitelist

    def evaluate_packet(self, packet_dict):
        """
        Evaluates a parsed packet dictionary against all NIDS rules.
        Returns a list of Alert dictionaries.
        """
        alerts = []
        src_ip = packet_dict.get('src')
        dst_ip = packet_dict.get('dst')
        now = time.time()

        if not src_ip or src_ip == "Unknown":
            return alerts

        # Skip rate alerts if src_ip is explicitly whitelisted (except payload inspection)
        whitelisted = self.is_whitelisted(src_ip)

        # ---------------- Rule 1: SQL Injection Detection (HIGH Severity) ----------------
        ascii_payload = packet_dict.get('ascii_payload', '').upper()
        raw_payload = packet_dict.get('raw_payload', b'')
        
        sqli_patterns = ["SELECT ", "UNION ", "DROP TABLE", "--", "OR 1=1", "OR '1'='1'", "INSERT INTO", "DELETE FROM"]
        found_sqli = [pat for pat in sqli_patterns if pat in ascii_payload]
        if found_sqli:
            alerts.append({
                "severity": "HIGH",
                "attack_type": "SQL_INJECTION",
                "rule_name": "Rule 1 - Web Application SQL Injection Pattern",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "description": f"Payload contained malicious SQL query signatures: {', '.join(found_sqli)}",
                "raw_payload": packet_dict.get('hex_dump', '')
            })

        if whitelisted:
            return alerts

        # ---------------- Rule 2: Port Scan Detection (HIGH Severity) ----------------
        # Threshold: >10 TCP SYN packets from same IP in 1.0 second window
        protocol = packet_dict.get('protocol', '')
        info = packet_dict.get('info', '')
        
        if protocol in ["TCP", "HTTP", "HTTPS"] and ("S" in info or "SYN" in info or "Seq=" in info):
            tracker = self.syn_tracker[src_ip]
            tracker.append(now)
            # Evict timestamps older than 1 second
            while tracker and (now - tracker[0] > 1.0):
                tracker.popleft()
                
            if len(tracker) >= 10:
                alerts.append({
                    "severity": "HIGH",
                    "attack_type": "PORT_SCAN",
                    "rule_name": "Rule 2 - High Rate TCP SYN Port Scan",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": f"Detected {len(tracker)} SYN connection attempts within 1.0 second.",
                    "raw_payload": packet_dict.get('hex_dump', '')
                })
                # Reset tracker after alert trigger to prevent spam
                tracker.clear()

        # ---------------- Rule 3: Ping Flood ICMP (MEDIUM Severity) ----------------
        # Threshold: >20 ICMP packets from same IP in 2.0 seconds window
        if protocol == "ICMP":
            tracker = self.icmp_tracker[src_ip]
            tracker.append(now)
            while tracker and (now - tracker[0] > 2.0):
                tracker.popleft()

            if len(tracker) >= 20:
                alerts.append({
                    "severity": "MEDIUM",
                    "attack_type": "PING_FLOOD",
                    "rule_name": "Rule 3 - ICMP Echo Request Flood",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": f"Detected {len(tracker)} ICMP packets in 2.0 seconds.",
                    "raw_payload": packet_dict.get('hex_dump', '')
                })
                tracker.clear()

        # ---------------- Rule 4: SSH Brute Force Attempt (MEDIUM Severity) ----------------
        # Threshold: >5 TCP connections to port 22 in 3.0 seconds window
        dst_port = packet_dict.get('dst_port')
        if dst_port == 22 or "-> 22" in info:
            tracker = self.ssh_tracker[src_ip]
            tracker.append(now)
            while tracker and (now - tracker[0] > 3.0):
                tracker.popleft()

            if len(tracker) >= 5:
                alerts.append({
                    "severity": "MEDIUM",
                    "attack_type": "BRUTE_FORCE_SSH",
                    "rule_name": "Rule 4 - SSH Port 22 Connection Spike",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": f"Detected {len(tracker)} connection attempts to SSH (Port 22) in 3.0 seconds.",
                    "raw_payload": packet_dict.get('hex_dump', '')
                })
                tracker.clear()

        # ---------------- Rule 5: ARP Spoofing Detection (HIGH Severity) ----------------
        # Check for IP address associated with multiple MAC addresses across packets
        if protocol == "ARP" and "Tell" in info:
            mac_address = packet_dict.get('ascii_payload', '')[:17]  # extract MAC if present
            if src_ip in self.ip_mac_table and mac_address and self.ip_mac_table[src_ip] != mac_address:
                old_mac = self.ip_mac_table[src_ip]
                alerts.append({
                    "severity": "HIGH",
                    "attack_type": "ARP_SPOOFING",
                    "rule_name": "Rule 5 - ARP Cache Poisoning / Spoofing",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": f"IP {src_ip} changed MAC address from {old_mac} to {mac_address}!",
                    "raw_payload": packet_dict.get('hex_dump', '')
                })
            elif mac_address:
                self.ip_mac_table[src_ip] = mac_address

        return alerts
