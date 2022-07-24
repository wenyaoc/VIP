import dpkt
import socket
from datetime import datetime
from dpkt.compat import compat_ord
import matplotlib.pyplot as plt
import itertools
import csv
import sys
import collections
import threading
from threading import Thread, local
import time
import os
from IpStat import IpStat
import pdb

window_size = 45
window_interval = 1
ratio = int(window_size/window_interval)



filename='./data/21Feb_pcap.pcap'
top_num = IpStat.top_num



def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def autopct_format(values):
    def my_format(pct):
        total = sum(values)
        val = int(round(pct*total/100.0))
        return '{:.1f}%\n({v:d})'.format(pct, v=val)
    return my_format

def plot_piechart(dic, chartName, threshold):
    newdic={}
    for key, group in itertools.groupby(dic, lambda k: 'All the rest' if (dic[k]<threshold) else k):
        newdic[key] = sum([dic[k] for k in list(group)])   

    labels = newdic.keys()
    sizes = newdic.values()
    fig, ax = plt.subplots()

    #ax.pie(sizes, labels=labels, autopct='%1.1f%%')
    ax.pie(sizes, labels=labels, autopct=autopct_format(sizes))
    ax.axis('equal')
    plt.tight_layout()
    plt.savefig(chartName)
    plt.show()


def write_csv(out_list):
    for output in out_list:
        writer.writerow(output)

def aggregate_window(sub_windows_list):
    None

# def get_attr_for_ip(ip_addr):
#     """Get a pre-defined set of attributes for the given IP address
#     list of attribute:
#     Categorical:
#         port being used and ranks (by activity - pkt, vol, etc)
#         network protocols
#         transport protocols
#         application protocols
#         packet types and their distributions (e.g., TCP flags - SYN, ACK, SYN-ACK etc)
#         packet content features (e.g., TCP window size for possible retransimission)

#     Quantitative attribute
#         packet count/volume to each port
#         difference between inbound and outbound packet/volume of entire/certain protocol
#         variance/periodicity of traffic (pkt, volume, etc) from different time of a host
#         packet length (in/out, protocols, avg, variance, etc)
#         (port, pkt, volume, transport type, duration, geographical, registry type, etc) distribution of external IPs/flows contacting a certain internal host

#         Args:
#             ip_addr
#         Returns:

#     """

#     # TCP/UDP ports and corresponding packet count/volume
#     filtered_packets = []
#     #packet filtering
#     for packet in packets:
#         if packet["IP.src"] == ip_addr or packet["IP.dst"] == ip_addr:
#             filtered_packets.append(packet)
    
#     # port statistic

#     total_size_in = 0
#     packet_in = 0
#     total_size_out = 0
#     packet_out = 0
#     ip_external_in = {}
#     ip_external_out = {}
#     ip_external_in_volume = {}
#     ip_external_out_volume = {}
#     port_in = {}
#     port_out = {}
#     port_in_volume = {}
#     port_out_volume = {}
#     currTime = filtered_packets[0]['TIME']
#     for packet in filtered_packets:
#         if (packet['TIME'] >= (currTime + 60)):

#             ip_external_in_occurrences = collections.Counter(ip_external_in)
#             ip_external_in_occurrences_volume = collections.Counter(ip_external_in_volume)
#             ranked_ip_external_in = ip_external_in_occurrences.most_common()
#             ranked_ip_external_in_volume = ip_external_in_occurrences_volume.most_common()
            
#             ip_external_out_occurrences = collections.Counter(ip_external_out)
#             ip_external_out_occurrences_volume = collections.Counter(ip_external_out_volume)
#             ranked_ip_external_out = ip_external_out_occurrences.most_common()
#             ranked_ip_external_out_volume = ip_external_out_occurrences_volume.most_common()

#             port_in_occurrences = collections.Counter(port_in)
#             port_in_occurrences_volume = collections.Counter(port_in_occurrences)
#             ranked_port_in = port_in_occurrences.most_common()
#             ranked_port_in_volume = port_in_occurrences_volume.most_common()

#             port_out_occurrences = collections.Counter(port_out)
#             port_out_occurrences_volume = collections.Counter(port_out_occurrences)
#             ranked_port_out = port_out_occurrences.most_common()
#             ranked_port_out_volume = port_out_occurrences_volume.most_common()

#             print(f"time {datetime.datetime.fromtimestamp(currTime).strftime('%Y-%m-%d %H:%M:%S')}")

#             print(f"total packet number (in): {packet_in}")
#             print(f"Avg size (in): {total_size_in/packet_in}")

#             print(f"total packet number (out): {packet_out}")
#             print(f"Avg size (out): {total_size_out/packet_out}")

#             print(f"# incoming IP: {len(ip_external_in_occurrences)}")
#             print(f"# outgoing IP: {len(ip_external_out_occurrences)}")

#             print("port_in_occurrences:")
#             print(port_in_occurrences)
#             print("port_out_occurrences:")
#             print(port_out_occurrences)

#             plot_piechart(ip_external_in_occurrences, f'./output/dpkt/myunsw23_ip_{currTime}_in_by_packet_number.jpg', 700)
#             plot_piechart(ip_external_out_occurrences, f'./output/dpkt/myunsw23_ip_{currTime}_out.jpg', 700)
#             plot_piechart(ip_external_in_occurrences_volume, f'./output/dpkt/myunsw23_ip_{currTime}_in_by_traffic_volume', 50000)
#             plot_piechart(ip_external_out_occurrences_volume, f'./output/dpkt/myunsw23_ip_{currTime}_in_by_traffic_volume', 50000)
#             #plot_piechart(port_in_occurrences, f'myunsw23_port_in.jpg', 0)
#             #plot_piechart(port_out_occurrences, f'myunsw23_port_out.jpg', 0)

#             total_size_in = 0
#             packet_in = 0
#             total_size_out = 0
#             packet_out = 0
#             ip_external_in.clear()
#             ip_external_out.clear()
#             port_in.clear()
#             port_out.clear()
#             currTime = packet['TIME']


#         else:
#             # outgoing packet
#             if packet['IP.src'] == ip_addr:
#                 # update external ip address bookkeeping
#                 if ip_external_out.get(packet['IP.dst']) == None:
#                     ip_external_out[packet['IP.dst']] = 1
#                     ip_external_out_volume[packet['IP.dst']] = packet['Size']
#                 else:
#                     ip_external_out[packet['IP.dst']] += 1
#                     ip_external_out_volume[packet['IP.dst']] += packet['Size']
#                 # update port number bookkeeping
#                 if port_out.get(packet['port.src']) == None:
#                     port_out[packet['port.src']] = 1
#                     port_out_volume[packet['port.src']] = packet['Size']
#                 else:
#                     port_out[packet['port.src']] += 1
#                     port_out_volume[packet['port.src']] += packet['Size']
                
#                 total_size_out += packet['Size']

#                 packet_out += 1

#             # incoming packet
#             else:
#                 # update external ip address bookkeeping
#                 if ip_external_in.get(packet['IP.src']) == None:
#                     ip_external_in[packet['IP.src']] = 1
#                     ip_external_in_volume[packet['IP.src']] = packet['Size']
#                 else:
#                     ip_external_in[packet['IP.src']] += 1
#                     ip_external_in_volume[packet['IP.src']] += packet['Size']
#                 # update port number bookkeeping
#                 if port_in.get(packet['port.dst']) == None:
#                     port_in[packet['port.dst']] = 1
#                     port_in_volume[packet['port.dst']] = packet['Size']
#                 else:
#                     port_in[packet['port.dst']] += 1 
#                     port_in_volume[packet['port.dst']] += packet['Size']
                
#                 total_size_in += packet['Size']
#                 packet_in += 1


#start_time = datetime.now()
'''header = ["IP", "host type", "start time", "end time", "#incoming packet%", "#outgoing packet%", "incoming traffic/byte%", "outgoing traffic/byte%", "avg incoming packet size", "avg outgoing packet size", \
        "top external IP%(pkt)", "top external IP%(size)", \
        "number of external IP", "top internal port(pkt)","top internal port(pkt)%", "top internal port(byte)", \
        "top internal port%(byte)","top external port(pkt)","top external port(pkt)%", "top external port(byte)","top external port(byte)%",\
        "top proto(pkt)", "top proto(pkt)%", "top proto(byte)", "top proto(byte)%"]'''

header =IpStat.OUTPUT_HEADER



csvf = open("./output/training/21Feb_train_SW.csv", 'w', encoding='UTF8', newline='')  
writer = csv.writer(csvf)
# write the header
writer.writerow(header)

f = open(filename, 'rb')
print("file successfully opened")
pcap = dpkt.pcap.Reader(f)

monitor_window = 60   # size of the time window in seconds, according to the pcap timestamp

# read target IPs and their types
target_IP_types = {}
ip_read = open('./data/Host-ShortList.csv', 'r', encoding='UTF8', newline='')
ip_reader = csv.reader(ip_read)
read_row = 0
for row in ip_reader:
    if read_row < 1:
        read_row += 1
        continue
    target_IP_types[row[0]] = row[2]
ip_read.close()
target_IPs = list(target_IP_types.keys())

p_id = None
p_time = None
p_size = None
p_eth_src = None
p_eth_dst = None
p_ip_src = None
p_ip_dst = None
p_proto = None
p_port_src = None
p_port_dst = None

# the local database is essentially is list of maximum length window_size/window_interval
# e.g. a window size of 60s and window interval of 10s give maximum length of 6
local_database = []

window_IpStats = None

# create the first entry of the local database(from time 0 - window_size)

#local_database.append(window1_stat)

#header = ['Packet ID', 'TIME', 'Size', 'eth.src', 'eth.dst', 'IP.src', 'IP.dst', 'IP.proto', 'port.src', 'port.dst']

curr_time = None
accumulated_window = 0
curr_stat = None


for timestamp, buf in pcap:
    if curr_time == None:
        curr_time = int(timestamp)

    if not curr_stat:
        curr_stat = IpStat(target_IPs, curr_time, curr_time + window_interval)
        #local_database.append(window1_stat)


    if (int(timestamp) < (curr_time + window_interval)):
        
 
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data

        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        link_layer_protocol = eth.get_type(eth.type).__name__

        srcport = 0
        dstport = 0
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            TCP = ip.data
            if str(type(TCP)) == "<class 'bytes'>":
                continue
            srcport = TCP.sport
            dstport = TCP.dport
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            UDP = ip.data
            if str(type(UDP)) == "<class 'bytes'>":
                continue
            srcport = UDP.sport
            dstport = UDP.dport
        else:
            continue

        # Print out the info
        # Print out the timestamp in UTC
        '''print(f'{count}. Timestamp: {datetime.datetime.utcfromtimestamp(timestamp)}, len: {len(buf)}')
        print(f'Ethernet Frame: {mac_addr(eth.src)}, {mac_addr(eth.dst)}, {eth.type}')
        print(f'IP: {inet_to_str(ip.src)} -> {inet_to_str(ip.dst)} proto: {ip.p}')
        print(f"port.src: {srcport}, port.dst: {dstport}")'''
        #   (len=%d ttl=%d DF=%d MF=%d offset=%d)')
        #      (, , ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
        # write the data

        # 
        #p_id = count
        p_time = int(timestamp)
        p_size = len(buf)
        p_eth_src = mac_addr(eth.src)
        p_eth_dst = mac_addr(eth.dst)
        p_ip_src = inet_to_str(ip.src)
        p_ip_dst = inet_to_str(ip.dst)
        p_proto = ip.get_proto(ip.p).__name__
        p_port_src = srcport
        p_port_dst = dstport


        # update the current entry of the local database with this packet's stat
        curr_stat.update_stat(p_size, p_eth_src, p_eth_dst, p_ip_src, p_ip_dst, p_proto, p_port_src, p_port_dst)
    
    else:
        # append currrent stat to local database
        local_database.append(curr_stat)
        # window is full
        if len(local_database) == ratio:
            # first time get full
            window_IpStats = local_database[0]
            for stat in local_database[1:]:
                #pdb.set_trace()
                window_IpStats += stat
            print("finish first round")
            write_csv(window_IpStats.analyze_features(target_IPs, target_IP_types))
            #pdb.set_trace()
                    
        elif len(local_database) == ratio + 1:
            if not window_IpStats:
                raise Exception("something went wrong")
            # remove the oldest entry, add the latest
            popped = local_database.pop(0)
            # window_IpStats -= popped
            # #print("popped {} to {}".format(popped.start_time, popped.end_time))
            # window_IpStats += curr_stat

            window_IpStats = local_database[0]
            for stat in local_database[1:]:
                #pdb.set_trace()
                window_IpStats += stat

            #print("added {} to {}".format(curr_stat.start_time, curr_stat.end_time))
            print("generating csv")
            write_csv(window_IpStats.analyze_features(target_IPs, target_IP_types))
            #pdb.set_trace()
        curr_time += window_interval

        # create a new entry
        curr_stat = IpStat(target_IPs, curr_time, curr_time + window_interval)
        

        
f.close()
csvf.close()

