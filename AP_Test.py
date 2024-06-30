import time
import threading
import logging
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq
from scapy.layers.l2 import LLC, SNAP, Dot1Q

# Configuration
SSID = "TestAP"
INTERFACE = "wlan0mon"
BSSID = "8E:B8:4A:75:E3:56"  # MAC address of the AP
CHANNEL = 1  # Channel number
BEACON_INTERVAL = 0.1024  # Beacon interval in seconds
CUSTOM_VSA = b'\xdd\x07\x00\x50\xf2\x02\x01\x01'  # Custom Vendor Specific Attribute (VSA)
VLAN_ID = 100  # VLAN ID for tagged frames

# Global sequence number
seq_num = 0

# Logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Track associated clients
associated_clients = set()

def get_sequence_number():
    global seq_num
    seq_num = (seq_num + 1) % 4096  # Sequence number is 12 bits (0-4095)
    logging.debug(f"Generated sequence number: {seq_num}")
    return seq_num

def create_element(id, info):
    logging.debug(f"Creating element with ID {id} and info {info}")
    return Dot11Elt(ID=id, info=info)

def create_beacon(ssid, bssid, channel):
    seq = get_sequence_number()
    logging.info(f"Creating beacon frame with sequence number: {seq}")
    beacon = RadioTap() / \
             Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=seq << 4) / \
             Dot11Beacon(cap=0x2104) / \
             create_element(0, ssid) / \
             create_element(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24') / \
             create_element(3, bytes([channel])) / \
             create_element(5, b'\x00\x01\x00\x00') / \
             create_element(7, b'\x07\x42\x55\x53\x00\x00') / \
             create_element(50, b'\x30\x48\x60\x6c') / \
             create_element(42, b'\x00') / \
             create_element(61, bytes([channel]) + b'\x01\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') / \
             create_element(221, CUSTOM_VSA)
    logging.debug(f"Beacon frame created: {beacon.summary()}")
    return beacon

def create_probe_response(bssid, src_mac):
    logging.info(f"Creating probe response for source MAC: {src_mac}")
    probe_response = RadioTap() / \
                     Dot11(type=0, subtype=5, addr1=src_mac, addr2=bssid, addr3=bssid) / \
                     Dot11Beacon(cap=0x2104) / \
                     create_element(0, SSID) / \
                     create_element(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24') / \
                     create_element(3, bytes([CHANNEL])) / \
                     create_element(7, b'\x07\x42\x55\x53\x00\x00') / \
                     create_element(50, b'\x30\x48\x60\x6c') / \
                     create_element(42, b'\x00') / \
                     create_element(61, bytes([CHANNEL]) + b'\x01\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') / \
                     create_element(221, CUSTOM_VSA)
    logging.debug(f"Probe response frame created: {probe_response.summary()}")
    return probe_response

def create_assoc_response(bssid, src_mac):
    logging.info(f"Creating association response for source MAC: {src_mac}")
    assoc_response = RadioTap() / \
                     Dot11(type=0, subtype=1, addr1=src_mac, addr2=bssid, addr3=bssid) / \
                     Dot11AssoResp(cap=0x2104, AID=1, status=0) / \
                     create_element(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24') / \
                     create_element(50, b'\x30\x48\x60\x6c') / \
                     create_element(3, bytes([CHANNEL])) / \
                     create_element(7, b'\x07\x42\x55\x53\x00\x00') / \
                     create_element(42, b'\x00') / \
                     create_element(61, bytes([CHANNEL]) + b'\x01\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') / \
                     create_element(221, CUSTOM_VSA)
    logging.debug(f"Association response frame created: {assoc_response.summary()}")
    return assoc_response

def send_beacon(interface):
    while True:
        try:
            beacon = create_beacon(SSID, BSSID, CHANNEL)
            sendp(beacon, iface=interface, verbose=False)
            logging.info(f"Beacon sent on interface {interface}")
            time.sleep(BEACON_INTERVAL)  # Send a beacon every 102.4 ms
        except Exception as e:
            logging.error(f"Error sending beacon: {e}")

def create_data_frame(src_mac, dst_mac, payload):
    logging.info(f"Creating data frame from {src_mac} to {dst_mac} with VLAN ID {VLAN_ID}")
    dot11 = Dot11(type=2, subtype=0, addr1=dst_mac, addr2=src_mac, addr3=BSSID)
    llc_snap = LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03) / SNAP(OUI=0x000000, code=0x8100)  # Using 0x8100 for VLAN
    vlan = Dot1Q(vlan=VLAN_ID)
    data_frame = RadioTap() / dot11 / llc_snap / vlan / payload
    logging.debug(f"Data frame created: {data_frame.summary()}")
    return data_frame

def send_data_frame(src_mac):
    dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast address
    payload = b"This is a test payload"  # Example payload
    data_frame = create_data_frame(src_mac, dst_mac, payload)
    sendp(data_frame, iface=INTERFACE, verbose=False)
    logging.info(f"Data frame sent from {src_mac} to {dst_mac}")

def packet_handler(packet):
    try:
        if packet.haslayer(Dot11ProbeReq):
            logging.info(f"Received Probe request from {packet.addr2}")
            probe_response = create_probe_response(BSSID, packet.addr2)
            sendp(probe_response, iface=INTERFACE, verbose=False)
            logging.info(f"Probe response sent to {packet.addr2}")

        elif packet.haslayer(Dot11AssoReq) and packet.addr1 == BSSID:
            logging.info(f"Received Association request from {packet.addr2}")
            assoc_response = create_assoc_response(BSSID, packet.addr2)
            sendp(assoc_response, iface=INTERFACE, verbose=False)
            logging.info(f"Association response sent to {packet.addr2}")
            associated_clients.add(packet.addr2)
            logging.info(f"Client {packet.addr2} associated successfully")
            send_data_frame(packet.addr2)
    except Exception as e:
        logging.error(f"Error handling packet: {e}")

if __name__ == "__main__":
    try:
        # Start sending beacons in a separate thread
        logging.info("Starting beacon thread")
        beacon_thread = threading.Thread(target=send_beacon, args=(INTERFACE,))
        beacon_thread.daemon = True
        beacon_thread.start()

        # Start sniffing for probe and association requests
        logging.info("Starting packet sniffing")
        sniff(iface=INTERFACE, prn=packet_handler)
    except KeyboardInterrupt:
        logging.info("Stopping the access point")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
