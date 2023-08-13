#!/usr/bin/env python3
# Task1-3.py

# Task 1.3
from scapy.all import *
import sys

a = IP()
a.dst = '8.8.4.4'
a.ttl = int(sys.argv[1])
b = ICMP()
#send(a/b)
a = sr1(a/b)
print("Source IP: ", a.src)