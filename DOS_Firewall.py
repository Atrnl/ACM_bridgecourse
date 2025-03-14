import time
import os
import platform
from collections import defaultdict
from scapy.all import sniff, IP

packet_count = defaultdict(int)
start_time = [time.time()]
blocked_ips = set()
THRESHOLD = 10  # Packets per second

def block_ip(ip):
    if ip in blocked_ips:
        return False #already blocked, do nothing
    if platform.system() == "Windows":
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    else:
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
    print(f"Blocked IP: {ip}")
    blocked_ips.add(ip)
    return True #IP blocked now

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        packet_count[src_ip] += 1
        
        current_time = time.time()
        time_interval=current_time - start_time[0]
        if time_interval >= 1:
            for ip, count in packet_count.items():
                rate = count / time_interval
                if rate > THRESHOLD:
                    if block_ip(ip):
                        print(f'Packet rate: {rate}')
            packet_count.clear()
            start_time[0] = current_time

sniff(filter="ip", prn=packet_callback, store=False)
