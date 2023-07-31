#! /usr/bin/env python3
from scapy.all import *
pkt = scapy.all.rdpcap('capture.pcap')
print(pkt) # print all packets

ip_saddr = [] # ip source addresses
ip_daddr = [] # ip destination addresses
local_sports = [] # local source ports
local_dports = [] # local destination ports

for pkt in pkt:
        if IP in pkt :
                if '192.168.1.' in pkt[IP].src: # display IP addresses in the ip range
                        ip_saddr.append(pkt[IP].src) 
                        if TCP in pkt : # display TCP ports in the ip range
                                local_sports.append(pkt[TCP].sport)
                                local_dports.append(pkt[TCP].dport)
                        if UDP in pkt : # display UDP ports in the ip range
                                local_sports.append(pkt[UDP].sport)
                                local_dports.append(pkt[UDP].dport)
                        if ICMP in pkt : # display ICMP ports in the ip range
                                local_sports.append(pkt[ICMP].sport)
                                local_dports.append(pkt[ICMP].dport)
                if '192.168.1.' in pkt[IP].dst:
                        ip_daddr.append(pkt[IP].dst)
                        if TCP in pkt :
                                local_sports.append(pkt[TCP].sport)
                                local_dports.append(pkt[TCP].dport)
                        if UDP in pkt :
                                local_sports.append(pkt[UDP].sport)
                                local_dports.append(pkt[UDP].dport)
                        if ICMP in pkt :
                                local_sports.append(pkt[ICMP].sport)
                                local_dports.append(pkt[ICMP].dport)

ips = list(dict.fromkeys(ip_saddr)) # remove duplicates
ipd = list(dict.fromkeys(ip_daddr))
ip_saddr = sorted(ips) # sort in order
ip_daddr = sorted(ipd)

local_sports = list(dict.fromkeys(local_sports))
local_dports = list(dict.fromkeys(local_dports))
local_sports = sorted(local_sports)
local_dports = sorted(local_dports)

print ("IP Source Addresses: ", ips)
print ("IP Destination Addresses: ", ipd)
print ("Local Source Ports: ", local_sports)
print ("Local Destination Ports: ", local_dports)
