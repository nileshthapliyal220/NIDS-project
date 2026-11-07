import gc
import os
from scapy.utils import PcapReader
from cicflowmeter.flow_session import generate_session_class
def extract_flows(pcap_path, csv_path):
    """Read a .pcap file and write one row per flow to csv_path."""
    if os.path.exists(csv_path):
        os.remove(csv_path)
    Session = generate_session_class("csv", csv_path, False)
    session = Session()
    for pkt in PcapReader(pcap_path):
        session.on_packet_received(pkt)
    session.garbage_collect(None)
    del session.output_writer
    gc.collect()
    return csv_path