from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
packets = rdpcap("data/first_capture.pcapng")
flows = {}
for pkt in packets:
    if IP not in pkt:
        continue
    if TCP in pkt:
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        continue
    end_a = (pkt[IP].src, sport)
    end_b = (pkt[IP].dst, dport)
    first, second = sorted([end_a, end_b])
    key = (first, second, proto)
    t = float(pkt.time)
    if key not in flows:
        flows[key] = {"packets": 0, "bytes": 0, "start": t, "end": t}
    flow = flows[key]
    flow["packets"] += 1
    flow["bytes"] += len(pkt)
    flow["start"] = min(flow["start"], t)
    flow["end"] = max(flow["end"], t)
rows = []
for (first, second, proto), f in flows.items():
    duration = f["end"] - f["start"]
    rows.append({
        "endpoint_a": f"{first[0]}:{first[1]}",
        "endpoint_b": f"{second[0]}:{second[1]}",
        "protocol": proto,
        "packets": f["packets"],
        "bytes": f["bytes"],
        "duration_s": round(duration, 3),
        "packets_per_s": round(f["packets"] / duration, 1) if duration > 0 else 0,
    })
df = pd.DataFrame(rows)
print("Total flows:", len(df))
print()
print(df.sort_values("packets", ascending=False).head(10).to_string(index=False))