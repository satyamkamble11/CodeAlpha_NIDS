import os
import time
from collections import defaultdict, deque

class RuleEngine:
    """
    Dynamic NIDS Signature and Threshold Rule Engine.
    Evaluates streaming network packets against customizable security detection rules.
    """
    def __init__(self, whitelist_file="whitelist.txt"):
        self.whitelist_file = whitelist_file
        self.whitelist = set()
        self.load_whitelist()

        # Dynamic Rule Thresholds (Can be tuned live in GUI)
        self.port_scan_threshold = 10     # SYN packets per second
        self.ping_flood_threshold = 20    # ICMP packets per 2 seconds
        self.ssh_bruteforce_threshold = 5 # SSH connections per 3 seconds

        # Sliding window state trackers
        self.syn_tracker = defaultdict(deque)
        self.icmp_tracker = defaultdict(deque)
        self.ssh_tracker = defaultdict(deque)
        self.ip_mac_table = {}

    def load_whitelist(self):
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

    def add_to_whitelist(self, ip_address):
        self.whitelist.add(ip_address.strip())
        try:
            with open(self.whitelist_file, "a") as f:
                f.write(f"\n{ip_address.strip()}")
        except Exception:
            pass

    def is_whitelisted(self, ip_address):
        return ip_address in self.whitelist

    def update_thresholds(self, port_scan, ping_flood, ssh_bruteforce):
        self.port_scan_threshold = int(port_scan)
        self.ping_flood_threshold = int(ping_flood)
        self.ssh_bruteforce_threshold = int(ssh_bruteforce)

    def evaluate_packet(self, packet_dict):
        alerts = []
        src_ip = packet_dict.get('src')
        dst_ip = packet_dict.get('dst')
        now = time.time()

        if not src_ip or src_ip == "Unknown":
            return alerts

        whitelisted = self.is_whitelisted(src_ip)

        # Rule 1: SQL Injection Detection
        ascii_payload = packet_dict.get('ascii_payload', '').upper()
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

        # Rule 2: Port Scan Detection
        protocol = packet_dict.get('protocol', '')
        info = packet_dict.get('info', '')
        
        if protocol in ["TCP", "HTTP", "HTTPS"] and ("S" in info or "SYN" in info or "Seq=" in info):
            tracker = self.syn_tracker[src_ip]
            tracker.append(now)
            while tracker and (now - tracker[0] > 1.0):
                tracker.popleft()
                
            if len(tracker) >= self.port_scan_threshold:
                alerts.append({
                    "severity": "HIGH",
                    "attack_type": "PORT_SCAN",
                    "rule_name": "Rule 2 - High Rate TCP SYN Port Scan",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": f"Detected {len(tracker)} SYN connection attempts within 1.0 second (Threshold: {self.port_scan_threshold}).",
                    "raw_payload": packet_dict.get('hex_dump', '')
                })
                tracker.clear()

        # Rule 3: Ping Flood ICMP
        if protocol == "ICMP":
            tracker = self.icmp_tracker[src_ip]
            tracker.append(now)
            while tracker and (now - tracker[0] > 2.0):
                tracker.popleft()

            if len(tracker) >= self.ping_flood_threshold:
                alerts.append({
                    "severity": "MEDIUM",
                    "attack_type": "PING_FLOOD",
                    "rule_name": "Rule 3 - ICMP Echo Request Flood",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": f"Detected {len(tracker)} ICMP packets in 2.0 seconds (Threshold: {self.ping_flood_threshold}).",
                    "raw_payload": packet_dict.get('hex_dump', '')
                })
                tracker.clear()

        # Rule 4: SSH Brute Force Attempt
        dst_port = packet_dict.get('dst_port')
        if dst_port == 22 or "-> 22" in info:
            tracker = self.ssh_tracker[src_ip]
            tracker.append(now)
            while tracker and (now - tracker[0] > 3.0):
                tracker.popleft()

            if len(tracker) >= self.ssh_bruteforce_threshold:
                alerts.append({
                    "severity": "MEDIUM",
                    "attack_type": "BRUTE_FORCE_SSH",
                    "rule_name": "Rule 4 - SSH Port 22 Connection Spike",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": f"Detected {len(tracker)} connection attempts to SSH (Port 22) in 3.0 seconds (Threshold: {self.ssh_bruteforce_threshold}).",
                    "raw_payload": packet_dict.get('hex_dump', '')
                })
                tracker.clear()

        # Rule 5: ARP Spoofing Detection
        if protocol == "ARP" and "Tell" in info:
            mac_address = packet_dict.get('ascii_payload', '')[:17]
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
