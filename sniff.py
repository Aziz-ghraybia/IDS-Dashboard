from sys import flags
from scapy.all import sniff, IP, TCP, UDP , conf
import time
import csv
from collections import defaultdict, deque
import os
import pandas as pd

# ===============================
# CONFIG
# ===============================
CAPTURE_TIME = 15          # seconds
FLOW_TIMEOUT = 60          # seconds
TIME_WINDOW = 2            # seconds
HOST_WINDOW_SIZE = 100

Permanent_LOG_FILE = "./Logs/sniffed_packets.csv"
RAW_LOG_FILE = "./Logs/raw_traffic_log.csv"

def keep_features(features):
    desired = [
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "land",
        "wrong_fragment",
        "urgent",
        "count",
        "srv_count",
        "same_srv_rate",
        "diff_srv_rate",
        "dst_host_count",
        "dst_host_srv_count",
        "dst_host_same_srv_rate"
    ]
    return features[desired]

TCP_SERVICE_MAP = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    43: "whois",
    53: "domain",
    79: "finger",
    80: "http",
    81: "http_8001",
    87: "link",
    95: "supdup",
    101: "hostnames",
    102: "iso_tsap",
    105: "csnet_ns",
    109: "pop_2",
    110: "pop_3",
    111: "sunrpc",
    113: "auth",
    119: "nntp",
    137: "netbios_ns",
    138: "netbios_dgm",
    139: "netbios_ssn",
    143: "imap4",
    179: "bgp",
    389: "ldap",
    443: "http_443",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    520: "efs",
    540: "uucp",
    543: "klogin",
    544: "kshell",
    1521: "sql_net",
    2784: "http_2784",
    6000: "X11",
    6667: "IRC",
    8001: "http_8001",
}

UDP_MAP = {
    7: "echo",
    9: "discard",
    13: "daytime",
    37: "time",
    53: "domain_u",
    69: "tftp_u",
    111: "sunrpc",
    123: "ntp_u",
    137: "netbios_ns",
    138: "netbios_dgm",
}
ICMP_MAP = {
    0: "ecr_i",     # Echo Reply
    8: "eco_i",     # Echo Request
    3: "urp_i",     # Destination Unreachable
    11: "tim_i",    # Time Exceeded
    13: "tim_i",    # Timestamp Request
    14: "tim_i",    # Timestamp Reply
}

# ===============================
# GLOBAL STATE
# ===============================
flows = {}
recent_connections = defaultdict(deque)
host_connections = defaultdict(lambda: deque(maxlen=HOST_WINDOW_SIZE))

feature_rows = []

# ===============================
# FLOW UTILITIES
# ===============================
def new_flow(pkt):
    return {
        "start_time": pkt["time"],
        "last_time": pkt["time"],
        "src_ip": pkt["src_ip"],
        "dst_ip": pkt["dst_ip"],
        "src_port": pkt["src_port"],
        "dst_port": pkt["dst_port"],
        "protocol": pkt["protocol"],
        "src_bytes": 0,
        "dst_bytes": 0,
        "flags": set(),
        "wrong_fragment": 0,
        "urgent": 0
    }

def flow_key(pkt):
    return (
        pkt["src_ip"],
        pkt["dst_ip"],
        pkt["src_port"],
        pkt["dst_port"],
        pkt["protocol"]
    )

def protocol_name(proto):
    if proto == 6:
        return "tcp"
    if proto == 17:
        return "udp"
    if proto == 1:
        return "icmp"
    return "other"

def service_name(port,protocol):
    if protocol == "tcp":
        return TCP_SERVICE_MAP.get(port, "other")
    if protocol == "udp":
        return UDP_MAP.get(port, "other")
    if protocol == "icmp":
        return ICMP_MAP.get(port, "other")
    return "other"

# ===============================
# FEATURE EXTRACTION
# ===============================
def extract_features(flow):
    now = time.time()

    # -------- BASIC FEATURES --------
    duration = flow["last_time"] - flow["start_time"]
    protocol = protocol_name(flow["protocol"])
    service = service_name(flow["dst_port"],protocol)
    src_bytes = flow["src_bytes"]
    dst_bytes = flow["dst_bytes"]

    land = int(
        flow["src_ip"] == flow["dst_ip"] and
        flow["src_port"] == flow["dst_port"]
    )

    wrong_fragment = flow["wrong_fragment"]
    urgent = flow["urgent"]

    # TCP flag logic (simplified)
    flags = flow["flags"]
    if "S" in flags and "F" in flags:
        flag = "SF"
    elif "S" in flags and "A" not in flags:
        flag = "S0"
    elif "R" in flags:
        flag = "REJ"
    else:
        flag = "OTH"

    # -------- TIME-BASED FEATURES --------
    src = flow["src_ip"]
    recent = recent_connections[src]

    # Remove old entries
    while recent and recent[0][0] < now - TIME_WINDOW:
        recent.popleft()

    count = len(recent)
    srv_count = sum(1 for x in recent if x[1] == service)

    same_srv_rate = srv_count / count if count > 0 else 0
    diff_srv_rate = 1 - same_srv_rate if count > 0 else 0

    # -------- HOST-BASED FEATURES --------
    dst = flow["dst_ip"]
    host_hist = host_connections[dst]

    dst_host_count = len(host_hist)
    dst_host_srv_count = sum(1 for x in host_hist if x[1] == service)

    dst_host_same_srv_rate = (
        dst_host_srv_count / dst_host_count if dst_host_count > 0 else 0
    )

    # -------- SAVE FEATURE ROW --------
    row = {
        "flow_id": f"{flow['src_ip']}:{flow['src_port']}-{flow['dst_ip']}:{flow['dst_port']}-{protocol}",
        "duration": round(duration),
        "protocol_type": protocol,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": land,
        "wrong_fragment": wrong_fragment,
        "urgent": urgent,
        "count": count,
        "srv_count": srv_count,
        "same_srv_rate": round(same_srv_rate, 2),
        "diff_srv_rate": round(diff_srv_rate, 2),
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate
    }

    feature_rows.append(row)

    # Update windows
    recent.append((now, service, flag))
    host_hist.append((now, service, flag))

# ===============================
# PACKET HANDLER
# ===============================
def on_packet(pkt):
    if IP not in pkt:
        return

    packet = {
        "time": time.time(),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": pkt[IP].proto,
        "length": len(pkt),
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "frag_offset": pkt[IP].frag
    }

    if TCP in pkt:
        packet["src_port"] = pkt[TCP].sport
        packet["dst_port"] = pkt[TCP].dport
        packet["tcp_flags"] = pkt[TCP].flags
    elif UDP in pkt:
        packet["src_port"] = pkt[UDP].sport
        packet["dst_port"] = pkt[UDP].dport
    else:
        return

    key = flow_key(packet)

    if key not in flows:
        flows[key] = new_flow(packet)

    flow = flows[key]
    flow["last_time"] = packet["time"]

    if packet["src_ip"] == flow["src_ip"]:
        flow["src_bytes"] += packet["length"]
    else:
        flow["dst_bytes"] += packet["length"]

    if packet["tcp_flags"]:
        if packet["tcp_flags"] & 0x02:
            flow["flags"].add("S")
        if packet["tcp_flags"] & 0x10:
            flow["flags"].add("A")
        if packet["tcp_flags"] & 0x01:
            flow["flags"].add("F")
        if packet["tcp_flags"] & 0x04:
            flow["flags"].add("R")
        if packet["tcp_flags"] & 0x20:
            flow["urgent"] += 1

    if packet["frag_offset"] > 0:
        flow["wrong_fragment"] += 1

    # Flow termination
    if packet["tcp_flags"] and packet["tcp_flags"] & 0x05:
        extract_features(flow)
        del flows[key]

# ===============================
# MAIN
# ===============================
def sniffing(adapter='Wi-Fi 2'):
    print("[*] Sniffing packets...")
    packets=sniff(timeout=CAPTURE_TIME, prn=on_packet) #,iface=adapter)  # Adjust iface as needed
    print("[*] Capture finished")
    # Save raw packets log
    raw_rows = []
    for p in packets:
        if IP not in p:
            continue
        raw_rows.append({
            "timestamp": p.time,
            "src_ip": p[IP].src,
            "dst_ip": p[IP].dst,
            "src_port": p[TCP].sport if TCP in p else None,
            "dst_port": p[TCP].dport if TCP in p else None,
            "protocol": p[IP].proto,
            "packet_len": len(p),
            "flags": p[TCP].flags if TCP in p else None,
            "frag_offset": p[IP].frag
        })
    if raw_rows:
        file_exists = os.path.isfile(RAW_LOG_FILE)
        with open(RAW_LOG_FILE, "a", newline="") as f_raw:
            writer = csv.DictWriter(f_raw, fieldnames=raw_rows[0].keys())
            if not file_exists:
                writer.writeheader()
            writer.writerows(raw_rows)

    # Close remaining flows
    for flow in list(flows.values()):
        extract_features(flow)
    # Write CSV
    if feature_rows:
        with open(Permanent_LOG_FILE, "a", newline="") as f2:
            file_exists = os.path.isfile(Permanent_LOG_FILE)
            writer = csv.DictWriter(f2, fieldnames=feature_rows[0].keys())
            if not file_exists:
                writer.writeheader()
            writer.writerows(feature_rows)

    print(f"[+] Features saved to {Permanent_LOG_FILE}")
    print(f"[+] Total flows: {len(feature_rows)}")
    df_features = pd.DataFrame(feature_rows)
    return [df_features['flow_id'], keep_features(df_features)]