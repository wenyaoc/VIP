import dpkt
import socket
import datetime
from dpkt.compat import compat_ord
import csv
import sys
import collections

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


def get_attr_for_ip(ip_addr):
    """Get a pre-defined set of attributes for the given IP address
    list of attribute:
    Categorical:
        port being used and ranks (by activity - pkt, vol, etc)
        network protocols
        transport protocols
        application protocols
        packet types and their distributions (e.g., TCP flags - SYN, ACK, SYN-ACK etc)
        packet content features (e.g., TCP window size for possible retransimission)

    Quantitative attribute
        packet count/volume to each port
        difference between inbound and outbound packet/volume of entire/certain protocol
        variance/periodicity of traffic (pkt, volume, etc) from different time of a host
        packet length (in/out, protocols, avg, variance, etc)
        (port, pkt, volume, transport type, duration, geographical, registry type, etc) distribution of external IPs/flows contacting a certain internal host

        Args:
            ip_addr
        Returns:

    """


    filtered_packets = []
    #packet filtering
    for packet in packets:
        




filename = sys.argv[1]
f = open(filename, 'rb')
pcap = dpkt.pcap.Reader(f)

header = ['Packet ID', 'TIME', 'Size', 'eth.src', 'eth.dst', 'IP.src', 'IP.dst', 'IP.proto', 'port.src', 'port.dst']
packets = []
count = 0
for timestamp, buf in pcap:
    count += 1

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
        srcport = TCP.sport
        dstport = TCP.dport
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
        UDP = ip.data
        srcport = UDP.sport
        dstport = UDP.dport
    else:
        continue

    # Print out the info
    # Print out the timestamp in UTC
    print(f'{count}. Timestamp: {datetime.datetime.utcfromtimestamp(timestamp)}, len: {len(buf)}')
    print(f'Ethernet Frame: {mac_addr(eth.src)}, {mac_addr(eth.dst)}, {eth.type}')
    print(f'IP: {inet_to_str(ip.src)} -> {inet_to_str(ip.dst)} proto: {ip.p}')
    print(f"port.src: {srcport}, port.dst: {dstport}")
    #   (len=%d ttl=%d DF=%d MF=%d offset=%d)')
    #      (, , ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
    # write the data
    data = [count, int(timestamp), len(buf), mac_addr(eth.src), mac_addr(eth.dst), inet_to_str(ip.src),
            inet_to_str(ip.dst), ip.p, srcport, dstport]
    packets.append(data)

f.close()

