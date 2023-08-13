#!/usr/bin/env python3
# Task1-1B.py

# Task 1.1B
from scapy.all import *

def print_pkt(pkt):
  pkt.show()

# Filter for TCP packet that comes from a particular IP and with a destination port number 23.
#pkt = sniff(iface='br-fbb94d193d5d', filter='tcp && src host 10.9.0.5 && dst port 23', prn=print_pkt)  

#Capture packets comes from or to go to a particular subnet.
pkt = sniff(iface='br-fbb94d193d5d', filter='net 128.230.0.0/16', prn=print_pkt)