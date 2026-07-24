import time
import sys
import argparse
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, send, sendp, Raw

def print_header(title):
    print("\n" + "="*60)
    print(f" 🔥 ATTACK SIMULATION: {title}")
    print("="*60)

def simulate_port_scan(target_ip="127.0.0.1", count=20):
    print_header(f"Port Scan (>10 SYN packets to {target_ip})")
    for i in range(count):
        port = 8000 + i
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
    print(f"✅ Sent {count} TCP SYN packets to ports 8000-{8000+count-1} rapidly.")

def simulate_ping_flood(target_ip="127.0.0.1", count=30):
    print_header(f"ICMP Ping Flood (>20 ICMP requests to {target_ip})")
    for i in range(count):
        pkt = IP(dst=target_ip)/ICMP()
        send(pkt, verbose=False)
        time.sleep(0.01)
    print(f"✅ Sent {count} ICMP Echo Request packets rapidly.")

def simulate_sqli(target_ip="127.0.0.1"):
    print_header(f"SQL Injection Web Attack Payload")
    sqli_payload = "GET /login?user=admin' UNION SELECT 1,username,password FROM users-- HTTP/1.1\r\nHost: target\r\n\r\n"
    pkt = IP(dst=target_ip)/TCP(dport=80, flags="PA")/Raw(load=sqli_payload)
    send(pkt, verbose=False)
    print(f"✅ Sent HTTP GET request with malicious payload: 'UNION SELECT username, password'")

def simulate_ssh_bruteforce(target_ip="127.0.0.1", count=8):
    print_header(f"SSH Port 22 Brute Force Attempt (>5 connections to {target_ip}:22)")
    for i in range(count):
        pkt = IP(dst=target_ip)/TCP(dport=22, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)
    print(f"✅ Sent {count} SSH TCP connection attempts to port 22.")

def simulate_arp_spoofing(target_ip="127.0.0.1"):
    print_header(f"ARP Cache Poisoning / Spoofing")
    # Send normal ARP
    pkt1 = ARP(op=2, pdst=target_ip, psrc="192.168.1.50", hwsrc="00:11:22:33:44:55")
    send(pkt1, verbose=False)
    time.sleep(0.1)
    # Send spoofed ARP with changed MAC
    pkt2 = ARP(op=2, pdst=target_ip, psrc="192.168.1.50", hwsrc="AA:BB:CC:DD:EE:FF")
    send(pkt2, verbose=False)
    print(f"✅ Sent ARP responses binding 192.168.1.50 to conflicting MAC addresses.")

def main():
    parser = argparse.ArgumentParser(description="CodeAlpha NIDS Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address for simulation (default: 127.0.0.1)")
    parser.add_argument("--attack", choices=["all", "portscan", "pingflood", "sqli", "ssh", "arp"], default="all", help="Attack simulation type")
    
    args = parser.parse_args()
    target = args.target

    print(f"🎯 Target IP for attack simulation: {target}")
    print("⏳ Make sure CodeAlpha NIDS dashboard (dashboard.py) is running to capture these alerts!\n")
    time.sleep(1)

    if args.attack == "portscan" or args.attack == "all":
        simulate_port_scan(target)
        time.sleep(1)

    if args.attack == "pingflood" or args.attack == "all":
        simulate_ping_flood(target)
        time.sleep(1)

    if args.attack == "sqli" or args.attack == "all":
        simulate_sqli(target)
        time.sleep(1)

    if args.attack == "ssh" or args.attack == "all":
        simulate_ssh_bruteforce(target)
        time.sleep(1)

    if args.attack == "arp" or args.attack == "all":
        simulate_arp_spoofing(target)
        time.sleep(1)

    print("\n🎉 Attack simulation completed! Check the NIDS GUI dashboard for generated alerts.")

if __name__ == '__main__':
    main()
