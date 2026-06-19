from datetime import datetime

rules = [
    {"id": 1, "action": "BLOCK", "ip": "192.168.1.105", "port": None, "protocol": None},
    {"id": 2, "action": "BLOCK", "ip": None, "port": 23, "protocol": "TCP"},
    {"id": 3, "action": "ALLOW", "ip": None, "port": 80, "protocol": "TCP"},
    {"id": 4, "action": "ALLOW", "ip": None, "port": 443, "protocol": "TCP"},
    {"id": 5, "action": "ALLOW", "ip": None, "port": 22, "protocol": "TCP"},
    {"id": 6, "action": "BLOCK", "ip": None, "port": 3389, "protocol": "TCP"},
]

def check_packet(ip, port, protocol):
    for rule in rules:
        ip_match = rule["ip"] is None or rule["ip"] == ip
        port_match = rule["port"] is None or rule["port"] == port
        proto_match = rule["protocol"] is None or rule["protocol"] == protocol.upper()

        if ip_match and port_match and proto_match:
            return rule["action"], rule["id"]

    return "ALLOW", None

def simulate():
    packets = [
        {"ip": "192.168.1.105", "port": 80, "protocol": "TCP"},
        {"ip": "10.0.0.55", "port": 23, "protocol": "TCP"},
        {"ip": "10.0.0.10", "port": 443, "protocol": "TCP"},
        {"ip": "10.0.0.20", "port": 3389, "protocol": "TCP"},
        {"ip": "10.0.0.30", "port": 22, "protocol": "TCP"},
        {"ip": "172.16.0.5", "port": 8080, "protocol": "TCP"},
    ]

    print("-" * 60)
    print(f"Firewall Rule Simulator — {datetime.now()}")
    print("-" * 60)

    for packet in packets:
        action, rule_id = check_packet(packet["ip"], packet["port"], packet["protocol"])
        rule_info = f"Rule #{rule_id}" if rule_id else "Default"
        status = "🔴 BLOCKED" if action == "BLOCK" else "🟢 ALLOWED"
        print(f"{status} | IP: {packet['ip']} | Port: {packet['port']} | {packet['protocol']} | {rule_info}")

    print("-" * 60)

if __name__ == "__main__":
    simulate()
