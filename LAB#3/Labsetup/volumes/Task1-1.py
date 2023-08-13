#!/usr/bin/env python3
# Task1-1.py

# Task 1.1

from scapy.all import *

def print_pkt(pkt):
  pkt.show()

pkt = sniff(iface='br-fbb94d193d5d', filter='icmp', prn=print_pkt)  

