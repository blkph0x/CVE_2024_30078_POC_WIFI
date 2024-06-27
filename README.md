### CVE-2024-30078:
# UPDATE 4
long over due update but.. WE HAVE A CRASH! more to come stay tuned.
# UPDATE 3
We have managed to get windows to accociate with our rouge AP and are able to send the dot11 data frame reqired to get into the function we are looking at. we will be moving the bulk of development to a private repo untill such times we get it working reliable and then we will merge with the public repo. please feel free to add any issues or ideas or findings you come across into the issues page i may also setup a discussions page.(I will) will update again around 9pm AEST 
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
