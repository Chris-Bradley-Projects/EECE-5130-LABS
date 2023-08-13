#!/usr/bin/env python3
# Task1-2.py

# Task 1.2
from scapy.all import *
a = IP()
a.dst = '1.2.3.4'
b = ICMP()
p = a/b

ls(a)

send(p, iface='br-fbb94d193d5d')

