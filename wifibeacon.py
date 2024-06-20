from scapy.all import *
import sys

def create_wifi_packet(ssid):
    MAX_SSID_LENGTH = 255
    
    # Break the SSID into chunks of MAX_SSID_LENGTH
    ssid_chunks = [ssid[i:i+MAX_SSID_LENGTH] for i in range(0, len(ssid), MAX_SSID_LENGTH)]

    # Iterate through the SSID chunks and send a beacon frame for each chunk
    for index, chunk in enumerate(ssid_chunks):
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=f'01:00:00:00:01:{index:02x}', addr3=f'02:00:00:00:01:{index:02x}')
        beacon = Dot11Beacon()
        essid = Dot11Elt(ID='SSID', info=chunk, len=len(chunk))
        frame = RadioTap()/dot11/beacon/essid

        print(f"Sending Beacon frame with SSID chunk {index+1}/{len(ssid_chunks)} of length: {len(chunk)}")

        try:
            sendp(frame, iface='wlan0', count=100, inter=0.1, verbose=1)
        except PermissionError:
            print("Error: You need root privileges to send packets.")
            return
        except Exception as e:
            print(f"An error occurred: {e}")
            return

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python wifibeacon.py <SSID>")
        sys.exit(1)

    ssid = sys.argv[1]
    create_wifi_packet(ssid)
