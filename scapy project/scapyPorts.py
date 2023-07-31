#! /usr/bin/env python3
from scapy.all import *
pkt = scapy.all.rdpcap('capture.pcap')
print(pkt) # print all packets

tcp_sports = []
tcp_dports = []
udp_sports = []
udp_dports = []
icmp_sports = []
icmp_dports = []

for pkt in pkts: 
        if TCP in pkt :
                tcp_sports.append(pkt[TCP].sport)
                tcp_dports.append(pkt[TCP].dport)
        if UDP in pkt :
                udp_sports.append(pkt[UDP].sport)
                udp_dports.append(pkt[UDP].dport)
        if ICMP in pkt :
                icmp_sports.append(pkt[ICMP].sport)
                icmp_dports.append(pkt[ICMP].dport)
        
tcp_sports = list(dict.fromkeys(tcp_sports)) # remove duplicates
tcp_dports = list(dict.fromkeys(tcp_dports)) 
tcp_sports = sorted(tcp_sports) # sort in order
tcp_dports = sorted(tcp_dports)
print ("TCP Source Ports: ", tcp_sports)
print ("TCP Destination Ports: ", tcp_dports)

udp_sports = list(dict.fromkeys(udp_sports))
udp_dports = list(dict.fromkeys(udp_dports))
udp_sports = sorted(udp_sports)
udp_dports = sorted(udp_dports)
print ("UDP Source Ports: ", udp_sports)
print ("UDP Destination Ports: ", udp_dports)

icmp_sports = list(dict.fromkeys(icmp_sports))
icmp_dports = list(dict.fromkeys(icmp_dports))
icmp_sports = sorted(icmp_sports)
icmp_dports = sorted(icmp_dports)
print ("ICMP Source Ports: ", icmp_sports)
print ("ICMP Destination Ports: ", icmp_dports)




        