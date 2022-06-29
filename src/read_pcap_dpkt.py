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
from threading import Thread
import time
import os

window_size = 10
filename='./data/21Feb_pcap.pcap'
#top_num = 3


class IpStat:
    def __init__(self, target_IPs) -> None:
        self.local_stat = {}
        self.target_IPs = target_IPs

    def update_stat(self, size, eth_src, eth_dst, ip_src, ip_dst, proto, port_src, port_dst):
        for ip in self.target_IPs:
            if (ip_src == ip or ip_dst == ip) and self.local_stat.get(ip) == None:
                self.local_stat[ip] = {}
                self.local_stat["totol incoming traffic by packet"] = 0
                self.local_stat["total incoming traffic by byte"] = 0
                self.local_stat["totol outgoing traffic by packet"] = 0
                self.local_stat["total outgoing traffic by byte"] = 0
                self.local_stat[ip]["incoming traffic"] = {}
                self.local_stat[ip]["incoming traffic"]["#packet"] = 0
                self.local_stat[ip]["incoming traffic"]["traffic in bytes"] = 0
                self.local_stat[ip]["outgoing traffic"] = {}
                self.local_stat[ip]["outgoing traffic"]["#packet"] = 0
                self.local_stat[ip]["outgoing traffic"]["traffic in bytes"] = 0
                self.local_stat[ip]["external IPs"] = {}
                self.local_stat[ip]["internal ports"] = {}
                self.local_stat[ip]["external ports"] = {}
                self.local_stat[ip]["protocols"] = {}

            if ip_src == ip:
                # outgoing packet
                self.local_stat["total outgoing traffic by packet"] += 1
                self.local_stat["total outgoing traffic by byte"] += size
                
                self.local_stat[ip]["outgoing traffic"]["#packet"] += 1
                self.local_stat[ip]["outgoing traffic"]["traffic in bytes"] += size
                


                if self.local_stat[ip]["external IPs"].get(ip_dst) == None:
                    self.local_stat[ip]["external IPs"][ip_dst] = {}
                    self.local_stat[ip]["external IPs"][ip_dst]["#incoming packet"] = 0
                    self.local_stat[ip]["external IPs"][ip_dst]["incoming traffic in bytes"] = 0
                    self.local_stat[ip]["external IPs"][ip_dst]["#outgoing packet"] = 0
                    self.local_stat[ip]["external IPs"][ip_dst]["outgoing traffic in bytes"] = 0
                
                if self.local_stat[ip]["internal ports"].get(port_src) == None:
                    self.local_stat[ip]["internal ports"][port_src] = {}
                    self.local_stat[ip]["internal ports"][port_src]["#packet"] = 0
                    self.local_stat[ip]["internal ports"][port_src]["traffic in bytes"] = 0

                if self.local_stat[ip]["external ports"].get(port_dst) == None:
                    self.local_stat[ip]["external ports"][port_dst] = {}
                    self.local_stat[ip]["external ports"][port_dst]["#packet"] = 0
                    self.local_stat[ip]["external ports"][port_dst]["traffic in bytes"] = 0

                if self.local_stat[ip]["protocols"].get(proto) == None:
                    self.local_stat[ip]["protocols"][proto] = {}
                    self.local_stat[ip]["protocols"][proto]["#packet"] = 0
                    self.local_stat[ip]["protocols"][proto]["traffic in bytes"] = 0

                # update info
                self.local_stat[ip]["external IPs"][ip_dst]["#outgoing packet"] += 1
                self.local_stat[ip]["external IPs"][ip_dst]["outgoing traffic in bytes"] += size

                self.local_stat[ip]["internal ports"][port_src]["#packet"] += 1
                self.local_stat[ip]["internal ports"][port_src]["traffic in bytes"] += size
                self.local_stat[ip]["external ports"][port_dst]["#packet"] += 1
                self.local_stat[ip]["external ports"][port_dst]["traffic in bytes"] += size

                self.local_stat[ip]["protocols"][proto]["#packet"] += 1
                self.local_stat[ip]["protocols"][proto]["traffic in bytes"] += size


            elif ip_dst == ip:
                # incoming packet

                self.local_stat["total incoming traffic by packet"] += 1
                self.local_stat["total incoming traffic by byte"] += size

                self.local_stat[ip]["incoming traffic"]["#packet"] += 1
                self.local_stat[ip]["incoming traffic"]["traffic in bytes"] += size
                
                if self.local_stat[ip]["external IPs"].get(ip_src) == None:
                    self.local_stat[ip]["external IPs"][ip_src] = {}
                    self.local_stat[ip]["external IPs"][ip_src]["#incoming packet"] = 0
                    self.local_stat[ip]["external IPs"][ip_src]["incoming traffic in bytes"] = 0
                    self.local_stat[ip]["external IPs"][ip_src]["#outgoing packet"] = 0
                    self.local_stat[ip]["external IPs"][ip_src]["outgoing traffic in bytes"] = 0

                if self.local_stat[ip]["internal ports"].get(port_dst) == None:
                    self.local_stat[ip]["internal ports"][port_dst] = {}
                    self.local_stat[ip]["internal ports"][port_dst]["#packet"] = 0
                    self.local_stat[ip]["internal ports"][port_dst]["traffic in bytes"] = 0

                if self.local_stat[ip]["external ports"].get(port_src) == None:
                    self.local_stat[ip]["external ports"][port_src] = {}
                    self.local_stat[ip]["external ports"][port_src]["#packet"] = 0
                    self.local_stat[ip]["external ports"][port_src]["traffic in bytes"] = 0
                
                if self.local_stat[ip]["protocols"].get(proto) == None:
                    self.local_stat[ip]["protocols"][proto] = {}
                    self.local_stat[ip]["protocols"][proto]["#packet"] = 0
                    self.local_stat[ip]["protocols"][proto]["traffic in bytes"] = 0

                # update info
                self.local_stat[ip]["external IPs"][ip_src]["#incoming packet"] += 1
                self.local_stat[ip]["external IPs"][ip_src]["incoming traffic in bytes"] += size

                self.local_stat[ip]["internal ports"][port_dst]["#packet"] += 1
                self.local_stat[ip]["internal ports"][port_dst]["traffic in bytes"] += size
                self.local_stat[ip]["external ports"][port_src]["#packet"] += 1
                self.local_stat[ip]["external ports"][port_src]["traffic in bytes"] += size

                self.local_stat[ip]["protocols"][proto]["#packet"] += 1
                self.local_stat[ip]["protocols"][proto]["traffic in bytes"] += size    

    '''
        Analyze local database and generate features
        return a 1 dimension dictionary
    '''
    # [ip, start_time, end_time, in rate, out rate, in bite, out bite, avg in size, avg out size, 
    # \ top ext ip by pkt, top ext ip by size, total ex IP, top in port(pkt/%/byte/%), top out port(pkt/%/byte/%), top proto(pkt/byte)]
    def analyze_features(self):
        out_list = []
        i = 0
        for ip in target_ips:
            # create empty row
            out_list.append([])

            # start to generate IP specific start
            out_list[i].append(ip)
            out_list[i].append(target_IP_types[ip])
            out_list[i].append(currTime)
            out_list[i].append(currTime + window_size)
            if self.local_stat.get(ip) == None:
                out_list[i].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "/", "/"])
                i += 1 
                continue

        # packet rate(incoming/outgoing/bidirection)
            out_list[i].append(self.local_stat[ip]["incoming traffic"]["#packet"]/window_size)
            out_list[i].append(self.local_stat[ip]["outgoing traffic"]["#packet"]/window_size)
        
        # byte rate(incoming/outgoing/bidirection)
            out_list[i].append(self.local_stat[ip]["incoming traffic"]["traffic in bytes"]/window_size)
            out_list[i].append(self.local_stat[ip]["outgoing traffic"]["traffic in bytes"]/window_size)
        
        # average packet size(incoming/outgoing)
            if out_list[i][-2] > 0:
                avg_in_size = self.local_stat[ip]["incoming traffic"]["traffic in bytes"]\
                            /self.local_stat[ip]["incoming traffic"]["#packet"]
            else:
                avg_in_size = 0

            if out_list[i][-1] > 0:
                avg_out_size = self.local_stat[ip]["outgoing traffic"]["traffic in bytes"]\
                            /self.local_stat[ip]["outgoing traffic"]["#packet"]
            else:
                avg_out_size = 0

            out_list[i].append(avg_in_size)
            out_list[i].append(avg_out_size)

        # external IPs
            ext_ip_list = list(self.local_stat[ip]["external IPs"].keys())
            max_pkt = 0
            max_size = 0
            total_pkt = 0
            total_size = 0
            ind = 0
            ex_ip_pkt = 'None'
            ex_ip_size = 'None'
            if len(ext_ip_list) > 0:
                for ext_ip in ext_ip_list:
                    pkt_n = self.local_stat[ip]["external IPs"][ext_ip]["#incoming packet"] + \
                            self.local_stat[ip]["external IPs"][ext_ip]["#outgoing packet"]
                    size_pkt = self.local_stat[ip]["external IPs"][ext_ip]["incoming traffic in bytes"] + \
                                self.local_stat[ip]["external IPs"][ext_ip]["outgoing traffic in bytes"]
                    total_pkt += pkt_n
                    total_size += size_pkt
                    if pkt_n > max_pkt:
                        max_pkt = pkt_n

                    if size_pkt > max_size:
                        max_size = size_pkt
                    ind += 1
                if total_pkt > 0:
                    ex_ip_pkt = max_pkt/total_pkt
                else :
                    ex_ip_pkt = 0
                
                if total_size > 0:
                    ex_ip_size = max_size/total_size
                else:
                    ex_ip_size = 0
            
            out_list[i].append(ex_ip_pkt)
            out_list[i].append(ex_ip_size)
            ext_ip_list = list(self.local_stat[ip]["external IPs"].keys())
            out_list[i].append(len(ext_ip_list))
        # ranked ports(internal/external)
            internal_port_list = list(self.local_stat[ip]["internal ports"].keys())
            max_pkt = 0
            max_size = 0
            total_pkt = 0
            total_size = 0
            max_ind_pkt = 0
            max_ind_size = 0
            ind = 0
            out_pkt = 'None'
            out_size = 'None'
            if len(internal_port_list) > 0:
                for port_n in internal_port_list:
                    pkt_n = self.local_stat[ip]["internal ports"][port_n]["#packet"]
                    size_pkt = self.local_stat[ip]["internal ports"][port_n]["traffic in bytes"]
                    total_pkt += pkt_n
                    total_size += size_pkt
                    if pkt_n > max_pkt:
                        max_pkt = pkt_n
                        max_ind_pkt = ind

                    if size_pkt > max_size:
                        max_size = size_pkt
                        max_ind_size = ind
                    ind += 1
                out_pkt = internal_port_list[max_ind_pkt]
                out_size = internal_port_list[max_ind_size]
            
            if total_pkt > 0:
                max_pkt = max_pkt/total_pkt
            
            if total_size > 0:
                max_size = max_size/total_size


            out_list[i].append(out_pkt)
            out_list[i].append(max_pkt)
            out_list[i].append(out_size)
            out_list[i].append(max_size)

            external_port_list = list(self.local_stat[ip]["external ports"].keys())
            max_pkt = 0
            max_size = 0
            total_pkt = 0
            total_size = 0
            max_ind_pkt = 0
            max_ind_size = 0
            ind = 0
            out_pkt = 'None'
            out_size = 'None'
            if len(external_port_list) > 0:
                for port_n in external_port_list:
                    pkt_n = self.local_stat[ip]["external ports"][port_n]["#packet"]
                    size_pkt = self.local_stat[ip]["external ports"][port_n]["traffic in bytes"]
                    total_pkt += pkt_n
                    total_size += size_pkt
                    if pkt_n > max_pkt:
                        max_pkt = pkt_n
                        max_ind_pkt = ind

                    if size_pkt > max_size:
                        max_size = size_pkt
                        max_ind_size = ind
                    ind += 1
                out_pkt = external_port_list[max_ind_pkt]
                out_size = external_port_list[max_ind_size]
            if total_pkt > 0:
                max_pkt = max_pkt/total_pkt
            
            if total_size > 0:
                max_size = max_size/total_size
            
            out_list[i].append(out_pkt)
            out_list[i].append(max_pkt)
            out_list[i].append(out_size)
            out_list[i].append(max_size)
        
        # protocol(bidirection)
            proto_list = list(self.local_stat[ip]["protocols"].keys())
            max_pkt = 0
            max_size = 0
            total_pkt = 0
            total_size = 0
            max_ind_pkt = 0
            max_ind_size = 0
            ind = 0
            out_pkt = 'None'
            out_size = 'None'
            if len(proto_list) > 0:
                for pro in proto_list:
                    pkt_n = self.local_stat[ip]["protocols"][pro]["#packet"]
                    size_pkt = self.local_stat[ip]["protocols"][pro]["traffic in bytes"]
                    total_pkt += pkt_n
                    total_size += size_pkt
                    if pkt_n > max_pkt:
                        max_pkt = pkt_n
                        max_ind_pkt = ind

                    if size_pkt > max_size:
                        max_size = size_pkt
                        max_ind_size = ind
                    ind += 1
                out_pkt = proto_list[max_ind_pkt]
                out_pkt_per = max_pkt/total_pkt
                out_size = proto_list[max_ind_size]
                out_size_per = max_size/total_size
            
            out_list[i].append(out_pkt)
            out_list[i].append(out_pkt_per)
            out_list[i].append(out_size)
            out_list[i].append(out_size_per)

            i += 1

        return out_list

    def clear(self):
        """Create an empty data structure for holding IP stats"""
        self.local_stat = {}
        


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
        print("hellos")



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

header = ["IP", "start time", "end time", "#incoming packet", "#outgoing packet", "incoming traffic/byte", "outgoing traffic/byte", "avg incoming packet size", "avg outgoing packet size", \
        "top external IP%(pkt)", "top external IP%(size)", \
        "number of external IP", "top internal port(pkt)","top internal port(pkt)%", "top internal port(byte)", \
        "top internal port%(byte)","top external port(pkt)","top external port(pkt)%", "top external port(byte)","top external port(byte)%",\
        "top proto(pkt)", "top proto(byte)"]
        
csvf = open("./output/training/21Feb_train.csv", 'w', encoding='UTF8', newline='')  
writer = csv.writer(csvf)
# write the header
writer.writerow(header)

f = open(filename, 'rb')
print("file successfully opened")
pcap = dpkt.pcap.Reader(f)

monitor_window = 60   # size of the time window in seconds, according to the pcap timestamp

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
# ips under monitoring
'''target_ips = ["129.94.0.197",\
    "129.94.0.196",\
    "129.94.0.193",\
    "129.94.0.192",\
    "149.171.124.33",\
    "149.171.144.58",\
    "149.171.197.177",\
    "129.94.52.190",\
    "149.171.144.50",\
    "149.171.194.50",\
    "149.171.184.237",\
    "149.171.155.194",\
    "149.171.105.163",\
    "129.94.164.21",\
    "149.171.207.19",\
    "149.171.99.112",\
    "149.171.99.18",\
    "149.171.194.17",\
    "149.171.193.32",\
    "129.94.8.226",\
    "129.94.8.238",\
    "129.94.8.163",\
    "129.94.8.160",\
    "129.94.8.77",\
    "129.94.8.81",\
    "129.94.8.173",\
    "129.94.8.237",\
    "149.171.12.3",\
    "129.94.254.213",\
    "149.171.66.213",\
    "149.171.0.34",\
    "149.171.133.31",\
    "149.171.148.27",\
    "129.94.183.252",\
    "149.171.168.194",\
    "149.171.29.35",\
    "149.171.99.123",\
    "149.171.99.99",\
    "149.171.99.94",\
    "149.171.99.185"\
    ]'''

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

# create local da'tabase
local_database = IpStat(target_ips)

#header = ['Packet ID', 'TIME', 'Size', 'eth.src', 'eth.dst', 'IP.src', 'IP.dst', 'IP.proto', 'port.src', 'port.dst']

currTime = None

#count = 0'
for timestamp, buf in pcap:
    if currTime == None:
        currTime = int(timestamp)

    if (int(timestamp) < (currTime + window_size)):
    

        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data

        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

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

        # update local database according to this packet
        local_database.update_stat(p_size, p_eth_src, p_eth_dst, p_ip_src, p_ip_dst, p_proto, p_port_src, p_port_dst)
    
    else:
        
        write_csv(local_database.analyze_features())
        local_database.clear()
        currTime += window_size
        
f.close()
csvf.close()

