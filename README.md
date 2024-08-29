### CVE-2024-30078:
# UPDATE 6
this may be the last update unless someone who undertsands the wifi stack a little better then myself
It appears that the exploitability of this vulnerability has been somewhat overstated. There are specific prerequisites that must be met for it to be exploited as it currently stands.

As previously noted, the native driver does not account for an additional 4 bytes when the EtherType is 0x8100 (VLAN tagged network). Since the packet is rewritten on the original buffer, this causes it to be processed 4 bytes ahead of where it should be, due to the expected but missing dot1q header. This not only corrupts the translated packet—resulting in it being discarded as invalid—but also leads to an overwrite of up to 2 bytes outside the MDL buffer that holds the packet.

But how feasible is this exploit?

In practice, it is not straightforward. There's a safeguard that ensures the 12 bits of the VLAN ID field must be zero at the location where the dot1q header was anticipated. To overflow the buffer, you cannot send these extra bytes, meaning you are reliant on the existing bytes in the memory. You could either send one zero byte after the SNAP header to overflow by one byte, or none at all to overflow by two bytes. However, brute-forcing to find a scenario where the two bytes following the buffer are both zero is challenging, as there are 65,535 possible combinations.

Moreover, the difficulty doesn't end there. The adjacent heap memory layout is critical. While you do control the 2 bytes that are overwritten (which would be the last 2 octets of the transmitter's MAC address), the actual content you overwrite is crucial in determining whether a crash occurs. If fortunate, you might overwrite a memory pointer that is later dereferenced, potentially causing a crash. However, the likelihood of this leading to remote code execution is extremely low. At a minimum, another vulnerability that can remotely leak a kernel pointer would be necessary.

In summary, the impact of this CVE appears to be considerably less severe than initially suggested in the Microsoft advisory. Exploiting it requires being on the same network as the target, brute-forcing a specific memory layout, and obtaining additional information to achieve anything beyond a Denial of Service (DoS).
# UPDATE 5
Sorry its been a long weekend.. The issue is in the LLC when vlan is set it should be 8 bytes unless its vlan then it requires 4 more bytes at the end that is what the patch checks. so in the unpatched version we have out of bounds read then at lines 113/114/115 the buffer is modified directily since our payload is 10 bytes long and it expects 12 bytes we will have a 2 byte write condtions where the last two bytes of the senders mac will be written.. putting together a write up and cases over this week in my spare time. i think i wrote that correctly its pretty vague but ill get that sorted.. 
# UPDATE 4
long over due update but.. WE HAVE A CRASH! more to come stay tuned.
# UPDATE 3
We have managed to get windows to accociate with our rouge AP and are able to send the dot11 data frame reqired to get into the function we are looking at. we will be moving the bulk of development to a private repo until such times we get it working reliable and then we will merge with the public repo. please feel free to add any issues or ideas or findings you come across into the issues page i may also setup a discussions page.(I will) will update again around 9pm AEST 
# UPDATE 2
I have added two files to assit with debugging the CVE
# UPDATE 1
### issue
So in reversing this cve I have identified perhapes two methods of exploitaion 1. An attacker may beable to send a crafted packet while authenticated to a network this is much harder and requires more moving parts. 2. the easy way identify probes make educated guess on whitch probes a device has used that does not require AUTHentication, Construct a Rouge AP using the details of the open network probe(may require so guess work) then wait for a device to auto join and send the contructed frames to reach the affected code path(Thats where im working now). On joining an open network the AP sends multiple frames that reach the affected code block(not with the desired flags) we can construct the frame to include the desired flags to reach the code that has been patched or not in this case to try and identify the point of exploitation. We seem to have enough infomation now for this to work. Just need to build it out and run a few test cases while kernel debugging.  
# INFO
This REPO does not seem to be hitting the same bug as in the stated CVE new information has came to my attention thaks to FarmPoet, The CVE-2024-30078 vulnerability is in Dot11Translate80211ToEthernetNdisPacket() of the native wifi windows driver (nwifi.sys) and a very specific frame needs to be constructed to even get to the vulnerable code path (which this code does not).
## Im working on it
I have identified the chnages in the function and am now working on reversing to construt the relivent frame required to gain code flow into this segment. 
# CVE-2024-30078 Exploit
## Overview

# Explanation
## How the Code Works
### Imports and Initialization: 
The script imports necessary modules from Scapy and the system module.
### SSID Chunking: 
The create_wifi_packet function breaks the provided SSID into chunks of 255 bytes each (the maximum length allowed per chunk).
### Frame Creation: 
For each chunk, a WiFi beacon frame is created. 
### The frame includes:
Dot11 header for specifying the frame type and addresses.
Dot11Beacon to indicate a beacon frame.
Dot11Elt to embed the SSID chunk.
### Sending Frames: 
Each frame is sent using the sendp function with specific parameters for interface, count, interval, and verbosity.
### Error Handling: 
The script checks for permission errors and other exceptions during packet sending.
Buffer Overflow Mechanism Windows handles SSIDs up to 512 bytes, which is above the WiFi standard. By sending SSID chunks that exceed this limit, 
a buffer overflow can be triggered in the Windows WiFi handling subsystem. This overflow can potentially allow an attacker to execute arbitrary code or cause a system crash.

## Potential Issues and Considerations

### Root Privileges: 
The script requires root privileges to send packets. Ensure you run the script with sudo.
### Interface Availability: 
The script assumes the wireless interface is wlan0. Adjust this if your interface has a different name.
### Permission and Dependency Errors: 
Ensure Scapy and its dependencies are properly installed. Handle permissions for accessing the network interface.
### Legal and Ethical Implications: 
Using this script to exploit the vulnerability on unauthorized networks is illegal and unethical. Use it only for authorized security testing and research purposes.
Disclaimer
This code is provided for educational purposes only. The author is not responsible for any damage caused by the misuse of this script. Use responsibly and only in environments where you have explicit permission to perform such testing.
