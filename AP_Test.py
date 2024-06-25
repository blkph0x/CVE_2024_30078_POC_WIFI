# work in progress
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq

SSID = "TestAP"
interface = "wlan0mon"
bssid = "02:00:00:00:01:00"  # MAC address of the AP

# Custom Vendor Specific Attribute (VSA)
custom_vsa = b'\xdd\x07\x00\x50\xf2\x02\x01\x01'

def create_beacon(ssid, bssid):
    beacon = RadioTap() / \
             Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / \
             Dot11Beacon(cap="ESS") / \
             Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) / \
             Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') / \
             Dot11Elt(ID="DSset", info=chr(6).encode()) / \
             Dot11Elt(ID="TIM", info=b'\x00\x01\x00\x00') / \
             Dot11Elt(ID="Vendor", info=custom_vsa)
    return beacon

def create_probe_response(bssid, src_mac):
    probe_response = RadioTap() / \
                     Dot11(type=0, subtype=5, addr1=src_mac, addr2=bssid, addr3=bssid) / \
                     Dot11Beacon(cap="ESS") / \
                     Dot11Elt(ID="SSID", info=SSID) / \
                     Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') / \
                     Dot11Elt(ID="DSset", info=chr(6).encode()) / \
                     Dot11Elt(ID="Vendor", info=custom_vsa)
    return probe_response

def create_assoc_response(bssid, src_mac):
    assoc_response = RadioTap() / \
                     Dot11(type=0, subtype=1, addr1=src_mac, addr2=bssid, addr3=bssid) / \
                     Dot11AssoResp(cap="ESS", AID=1, status=0) / \
                     Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') / \
                     Dot11Elt(ID="Extended Rates", info=b'\x30\x48\x60\x6c') / \
                     Dot11Elt(ID="DSset", info=chr(6).encode()) / \
                     Dot11Elt(ID="Vendor", info=custom_vsa)
    return assoc_response

def send_beacon(interface, beacon):
    sendp(beacon, iface=interface, inter=0.1, loop=1, verbose=False)

def packet_handler(packet):
    if packet.haslayer(Dot11ProbeReq):
        print(f"Probe request from {packet.addr2}")
        probe_response = create_probe_response(bssid, packet.addr2)
        sendp(probe_response, iface=interface, verbose=False)
        print(f"Probe response sent to {packet.addr2}")

    elif packet.haslayer(Dot11AssoReq) and packet.addr1 == bssid:
        print(f"Association request from {packet.addr2}")
        assoc_response = create_assoc_response(bssid, packet.addr2)
        sendp(assoc_response, iface=interface, verbose=False)
        print("Association response sent")

if __name__ == "__main__":
    # Set up beacon
    beacon = create_beacon(SSID, bssid)
    
    # Start sending beacon in a separate thread
    import threading
    beacon_thread = threading.Thread(target=send_beacon, args=(interface, beacon))
    beacon_thread.daemon = True
    beacon_thread.start()
    
    # Start sniffing for probe and association requests
    sniff(iface=interface, prn=packet_handler)
