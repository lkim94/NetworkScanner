# NetworkScanner
A simple Python program for scanning hosts inside a network.
Scanned result outputs basic information about the hosts inside a target network such as IP address, MAC address, and OS.
Enabling OS scan will make the scan to take longer to finish.
This program is to be used for educational and security testing purposes only and I'm not responsible for the misuse of this program.

## Tested On
- Kali Linux 2021.1
- Windows 10
[!] OS scan doesn't work if you are running this program from Windows system. [!]

## Requirements
- scapy module ```pip3 install scapy```
- nmap3 module ```pip3 install python3-nmap```

## Usage
- ```sudo python3 NetworkScanner.py -t 192.168.1.1/24 -o``` --- Performs network scan on subnet 192.168.1.0/24 with OS scan.
- ```sudo python3 NetworkScanner.py -t 192.168.1.1/24``` --- Performs network scan on subnet 192.168.1.0/24 without OS scan.
