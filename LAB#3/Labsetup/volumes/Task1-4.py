#!/usr/bin/env python3
# Task1-4.py

# Task 1.4

import sys
import os
from scapy.all import *

def spoofing(pkt):

    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Packet")
        print("Source IP- ", pkt[IP].src)
        print("Dest IP- ", pkt[IP].dst)

        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        spoof = ip/icmp/data

        print("Spoofed Packet")
        print("Source IP- ", spoof[IP].src)
        print("Dest IP- ", spoof[IP].dst)

        send(spoof, verbose=0)

#filter = 'icmp and host 1.2.3.4'
#filter = 'icmp and host 10.9.0.99'
filter = 'icmp and host 8.8.8.8'
print(" {}\n".format(filter))
pkt = sniff(iface='br-fbb94d193d5d', filter=filter, prn=spoofing)