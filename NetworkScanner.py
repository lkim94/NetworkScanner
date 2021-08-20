#!/usr/bin/env python3

# AUTHOR
# lkim94

# DESCRIPTION
# This is a simple Python program for scanning a network.
# Scanned result outputs basic information about the hosts inside a target network such as IP address, MAC address, and OS.

# TESTED ON:
# Kali Linux 2021.1
# Windows 10 [!] Performing the OS scan using Windows systems doesn't work. [!]

# REQUIREMENTS
# scapy module must be installed. >>> pip3 install scapy
# nmap3 module must be installed. >>> pip3 install python3-nmap

# USAGE
# python3 NetworkScanner.py -t 192.168.1.1/24 -o --- Performs network scan on subnet 192.168.1.0/24 with OS scan.
# python3 NetworkScanner.py -t 192.168.1.1/24 --- Performs network scan on subnet 192.168.1.0/24 without OS scan.

import argparse, sys, re, nmap3
import scapy.all as scapy

nmap = nmap3.Nmap()

# Function for taking user input and arguments.
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', "--target", dest="target", help="Specifies target IP or target IP range to scan. Format: x.x.x.x or x.x.x.x/x")
    parser.add_argument('-o', help="Enables OS scan. This is loud and can be detected by firewalls or AV.", action="store_true")
    value = parser.parse_args()

    format = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?")
    target = format.search(str(value.target))
    scan_os = value.o

    if not target:
        while not target:
            target = format.search(input("\n[!]ERROR: Please provide target IP or target IP range in the correct format: "))
    print(f"\n[+] Target IP(range): {target.group()}")

    if scan_os:
        continue_scan = input("[+] OS scan enabled. OS scan provides the best guess for OS. This scan might raise an alarm on the target network or system.\n[+] Do you want to continue the scan? y/n: ")
        while continue_scan not in ['y', 'n']:
            continue_scan = input("[!] Please enter 'y' or 'n': ")
        if continue_scan == 'n':
            print("\n[+] Exiting the program.")
            sys.exit()
    else:
        print("[+] OS scan not enabled.")

    return target.group(), scan_os

# Function for scanning the target network.
def scan(target, scan_os):
    arp_message = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp = broadcast/arp_message
    print("[+] Scanning...")
    responses = scapy.srp(broadcast_arp, timeout=1, verbose=False)[0]
    client_list = []
    for response in responses:
        ip = response[1].psrc
        mac = response[1].hwsrc

        if scan_os:
            try:
                os = nmap.nmap_os_detection(ip)[str(ip)]['osmatch'][0]['name']
            except IndexError:
                os = "Could not identify"
            client_dict = {"IP": ip, "MAC": mac, "OS": os}
        else:
            client_dict = {"IP": ip, "MAC": mac}

        client_list.append(client_dict)
    return client_list

# Function for printing the scan result.
def print_results(result, scan_os):
    if scan_os:
        print("\nIP\t\tMAC\t\t\tOS Guess\n---------------------------------------------------------------------------")
        for element in result:
            print(f"{element['IP']}\t{element['MAC']}\t{element['OS']}")
    else:
        print("\nIP\t\tMAC\n---------------------------------")
        for element in result:
            print(f"{element['IP']}\t{element['MAC']}")
    print("\n[+] Scan Complete!\n")

#_______________________________________________________________________________________________________________________

user_input = get_arguments()
target = user_input[0]
scan_os = user_input[1]

scan_result = scan(target, scan_os)

print_results(scan_result, scan_os)
