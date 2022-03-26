from scapy.all import *
import csv

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

header = ['Packet ID', 'TIME', 'Size', 'eth.src', 'eth.dst', 'IP.src', 'IP.dst', 'IP.proto', 'port.src', 'port.dst']

scapy_cap = rdpcap(r'23Mar.pcap')
pid = 1

with open('23Mar.csv', 'w', encoding='UTF8', newline='') as f:
    writer = csv.writer(f)
    # write the header
    writer.writerow(header)

    for frame in scapy_cap:
        if (frame.haslayer("TCP") or frame.haslayer("UDP")) and frame.haslayer("IP"):
            packetMAC = frame[Ether]
            srcMAC = packetMAC.src
            dstMAC = packetMAC.dst
            packetIP = frame[IP]
            srcIP = packetIP.src
            dstIP = packetIP.dst
            protoIP = packetIP.proto
            sport = 0
            dport = 0
            if frame.haslayer("TCP"):
                packetTCP = frame[TCP]
                sport = packetTCP.sport
                dport = packetTCP.dport
            if frame.haslayer("UDP"):
                packetUDP = frame[UDP]
                sport = packetUDP.sport
                dport = packetUDP.dport    
            # print("----------------------------")
            # print(f"no: {pid}, TIME: {int(frame.time)}, eth.src: {srcMAC}, eth.dst: {dstMAC}")
            # print(f"ip.src: {srcIP}, ip.dst: {dstIP}, ip.proto: {protoIP}, port.src: {sport}, port.dst: {dport}")
            
            # write the data
            data = [pid, int(frame.time), len(frame), srcMAC, dstMAC, srcIP, dstIP, protoIP, sport, dport]
            writer.writerow(data)
        pid += 1
