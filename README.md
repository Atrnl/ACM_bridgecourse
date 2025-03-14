# DoS Blocker Firewall

The DoS Firewall is a Python-based security solution that detects and mitigates Denial-of-Service (DoS) attacks using Scapy. It monitors network traffic in real-time, identifying and blocking malicious IPs to enhance system security and stability.

Features:
1. Real-time Traffic Monitoring
2. Rate-Based IP Blocking
3. Dynamic Firewall Rules
4. Lightweight & Efficient
5. Logging & Alerting

How It Works
 -  The script continuously monitors network packets using Scapy.
 -  It tracks packet rates per IP and calculates the request frequency.
 -  If an IP exceeds the defined threshold, it is blocked using firewall rules.
 -  The system prevents redundant blocking and clears counters periodically.
