import os
import traceback
from scapy.utils import PcapReader
from cicflowmeter.flow_session import generate_session_class
from cicflowmeter.features.context import PacketDirection, get_packet_flow_key
PCAP = "data/my_first_capture.pcap"
OUT = "data/my_flows.csv"
Session = generate_session_class("csv", OUT, True)
session = Session()
total = 0
key_errors = 0
shown = False
for pkt in PcapReader(PCAP):
    total += 1
    try:
        get_packet_flow_key(pkt, PacketDirection.FORWARD)
    except Exception:
        key_errors += 1
        if not shown:
            shown = True
            print("First flow-key error (this is normal for non-TCP/UDP packets):")
            traceback.print_exc()
    session.on_packet_received(pkt)
print()
print("Packets read:", total)
print("Packets that failed the flow-key step:", key_errors)
print("Flows held in memory before flush:", len(session.flows))
import gc
session.garbage_collect(None)
del session.output_writer
gc.collect()
print("CSV size after flush (bytes):", os.path.getsize(OUT))