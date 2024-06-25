#work in progress you will need to make chnages to this for it to work in the way we intend some things changed for public release
from scapy.all import RadioTap, Dot11, LLC, SNAP, Dot1Q, sendp

def create_80211_frame_with_llc_vlan(bssid, dst_mac, src_mac, vlan_id, payload):
    # 802.11 Data Frame
    dot11 = Dot11(type=2,  # Data frame
                  subtype=0,  # Subtype data
                  addr1=dst_mac,  # Destination MAC
                  addr2=src_mac,  # Source MAC
                  addr3=bssid)  # BSSID

    # Logical Link Control (LLC) header
    llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)  # SNAP follows

    # SNAP header with EtherType for VLAN (need to chnage UOI to complie simple fix)
    snap = SNAP(OUI=b'\x00\x00\x00', code=0x8100)  # OUI for Ethernet, EtherType for VLAN-tagged frames

    # VLAN tag
    vlan = Dot1Q(vlan=vlan_id)

    # Construct the frame
    frame = RadioTap() / dot11 / llc / snap / vlan / payload
    return frame

def send_80211_frame(frame, iface='wlan0mon'):
    sendp(frame, iface=iface, verbose=False)
    print("802.11 frame with LLC and VLAN tag sent")

if __name__ == "__main__":
    # Example parameters
    bssid = '00:11:22:33:44:66'  # BSSID of the access point
    dst_mac = 'ff:ff:ff:ff:ff:ff'  # Destination MAC address (broadcast)
    src_mac = '00:11:22:33:44:55'  # Source MAC address (your device)
    vlan_id = 100  # VLAN ID (example)
    payload = b'Hello, this is a test payload.'  # Payload

    frame = create_80211_frame_with_llc_vlan(bssid, dst_mac, src_mac, vlan_id, payload)
    send_80211_frame(frame)
