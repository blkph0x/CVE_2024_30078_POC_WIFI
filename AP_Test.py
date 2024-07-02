import time
import threading
import logging
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11ProbeReq, Dot11ProbeResp, Dot11QoS
from scapy.layers.l2 import LLC, SNAP, Dot1Q

# Configuration
SSID = "TestAP"
INTERFACE = "wlan0mon"
BSSID = "8E:B8:4A:75:E3:56"
CHANNEL = 1
BEACON_INTERVAL = 0.1024
CUSTOM_VSA = b'\xdd\x07\x00\x50\xf2\x02\x01\x01'
VLAN_ID = 100

# Global sequence number
seq_num = 0

# Logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Track associated clients and their states
clients = {}
sent_data_frames = {}

ACK_TIMEOUT = 1  # Timeout in seconds for waiting ACKs

def get_sequence_number():
    global seq_num
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

def create_auth_response(bssid, src_mac):
    seq = 0
    logging.info(f"Creating authentication response for source MAC: {src_mac}")
    auth_response = RadioTap() / \
                    Dot11(type=0, subtype=11, addr1=src_mac, addr2=bssid, addr3=bssid, SC=seq << 4) / \
                    Dot11Auth(seqnum=2, status=0)
    logging.debug(f"Authentication response frame created: {auth_response.summary()}")
    return auth_response

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

def create_data_frame(src_mac, dst_mac, payload):
    seq = get_sequence_number()
    logging.info(f"Creating data frame from {src_mac} to {dst_mac} with VLAN ID {VLAN_ID}")
    dot11 = Dot11(type=2, subtype=0, addr1=dst_mac, addr2=src_mac, addr3=BSSID, SC=seq << 4)
    llc_snap = LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03) / SNAP(OUI=0x000000, code=0x8100)
    vlan = Dot1Q(vlan=VLAN_ID)
    data_frame = RadioTap() / dot11 / llc_snap / vlan / payload
    logging.debug(f"Data frame created: {data_frame.summary()}")
    return data_frame

def send_data_frame(src_mac, dst_mac, payload):
    data_frame = create_data_frame(src_mac, dst_mac, payload)
    seq = data_frame[Dot11].SC >> 4
    sent_data_frames[seq] = {'frame': data_frame, 'timestamp': time.time()}
    sendp(data_frame, iface=INTERFACE, verbose=False)
    logging.info(f"Data frame sent from {src_mac} to {dst_mac}")

def packet_handler(packet):
    try:
        if packet.haslayer(Dot11ProbeReq):
            logging.info(f"Received Probe request from {packet.addr2}")
            probe_response = create_probe_response(BSSID, packet.addr2)
            sendp(probe_response, iface=INTERFACE, verbose=False)
            logging.info(f"Probe response sent to {packet.addr2}")

        elif packet.subtype == 11:
            logging.info(f"Received Authentication request from {packet.addr2}")
            auth_response = create_auth_response(BSSID, packet.addr2)
            sendp(auth_response, iface=INTERFACE, verbose=False)
            logging.info(f"Authentication response sent to {packet.addr2}")

        elif packet.haslayer(Dot11AssoReq) and packet.addr1 == BSSID:
            logging.info(f"Received Association request from {packet.addr2}")
            assoc_response = create_assoc_response(BSSID, packet.addr2)
            sendp(assoc_response, iface=INTERFACE, verbose=False)
            logging.info(f"Association response sent to {packet.addr2}")
            
            # Handle association success
            clients[packet.addr2] = {'associated': True}
            logging.info(f"Client {packet.addr2} associated successfully")
            
            # Send VLAN-tagged data frame immediately after association
            send_data_frame(BSSID, packet.addr2, b"This is a VLAN-tagged data frame payload")

        elif packet.type == 0 and packet.subtype == 13:  # ACK frame
            seq = packet.SC >> 4
            if seq in sent_data_frames:
                logging.info(f"Received ACK for sequence number: {seq}")
                del sent_data_frames[seq]

        elif packet.type == 2:  # Data frame
            logging.info(f"Received data frame from {packet.addr2} to {packet.addr1}")
            if packet.addr1 in clients:  # Forward to another client
                sendp(packet, iface=INTERFACE, verbose=False)
                logging.info(f"Forwarded data frame to client {packet.addr1}")
            else:  # Forward to the internet
                send(packet)  # Sending out without RadioTap header for internet
                logging.info(f"Forwarded data frame to the internet")

    except Exception as e:
        logging.error(f"Error handling packet: {e}")

def retransmit_data_frames():
    while True:
        current_time = time.time()
        for seq, frame_info in list(sent_data_frames.items()):
            if current_time - frame_info['timestamp'] > ACK_TIMEOUT:
                logging.warning(f"Retransmitting data frame with sequence number: {seq}")
                sendp(frame_info['frame'], iface=INTERFACE, verbose=False)
                sent_data_frames[seq]['timestamp'] = current_time
        time.sleep(0.1)

if __name__ == "__main__":
    try:
        logging.info("Starting beacon thread")
        beacon_thread = threading.Thread(target=send_beacon, args=(INTERFACE,))
        beacon_thread.daemon = True
        beacon_thread.start()

        logging.info("Starting retransmission thread")
        retransmission_thread = threading.Thread(target=retransmit_data_frames)
        retransmission_thread.daemon = True
        retransmission_thread.start()

        logging.info("Starting packet sniffing")
        sniff(iface=INTERFACE, prn=packet_handler)
    except KeyboardInterrupt:
        logging.info("Stopping the access point")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
