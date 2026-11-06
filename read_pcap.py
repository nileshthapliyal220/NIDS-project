from scapy.all import rdpcap, IP, TCP,UDP
packets=rdpcap("data/first_capture.pcapng")
print("Total packets: ",len(packets))
print()
for num,pkt in enumerate(packets[:10],start=1):
    if IP in pkt:
        src=pkt[IP].src
        dst=pkt[IP].dst
        if TCP in pkt:
            protocol="TCP"
            ports=f"{pkt[TCP].sport} -> {pkt[TCP].dport}"
        elif UDP in pkt:
            protocol="UDP"
            ports=f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
        else:
            protocol="other"
            ports="-"
        print(f"#{num}: {src} -> {dst} | {protocol} | ports {ports} | {len(pkt)} bytes")
    else:
        print(f"#{num}: (not an IPv4 packet)")
from collections import Counter
protocol_count = Counter()
source_count = Counter()
for pkt in packets:
    if IP in pkt:
        source_count[pkt[IP].src] += 1
        if TCP in pkt:
            protocol_count["TCP"] += 1
        elif UDP in pkt:
            protocol_count["UDP"] += 1
        else:
            protocol_count["other IP"] += 1
    else:
        protocol_count["non-IP"] += 1
print()
print("Packets per protocol:")
for name, count in protocol_count.most_common():
    print(f"  {name}: {count}")
print()
print("Top 5 source IP addresses:")
for ip, count in source_count.most_common(5):
    print(f"  {ip}: {count} packets")