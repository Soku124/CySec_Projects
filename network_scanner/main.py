#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # creating ARP request with target IP / IP range

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Ethernet frame for broadcasting to all devices in the network


    arp_request_broadcast = broadcast/arp_request # combining both frames to create an ARP packet
    

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # send ARP broadcast at Layer 2 and receive replies from active hosts only


    
    clients_list = []  # creating the list of live host which contain dict of ip and mac address
    for element in answered_list:
        client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc} # dict going to append in list of live hosts
        clients_list.append(client_dict) # append dict of live host into client list

    return clients_list

def print_result(results_list): # function to print the result of the scan
    print("IP\t\t\t\tMAC Address\n"+"-"*60+"\n")
    for element in results_list:
        print(element["ip"]+"\t\t\t"+element["mac"])
        
options = get_arguments()

scan_result = scan(options.target)
print_result(scan_result)