from unicodedata import name
import dpkt
import socket
import csv
from dpkt.compat import compat_ord

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

def write_in(wt, in_dic, in_list):
    if type(in_dic) != type(dict()):
        in_list.append(str(in_dic))
        wt.writerow(in_list)
        in_list.pop(-1)
    else:
        for key, value in in_dic.items():
            in_list.append(key)
            write_in(wt, value, in_list)
            in_list.pop(-1)

property_ip_list = []
name_list = []
in_ip_dict = dict()

with open('ips.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        key = line.split( )
        property_ip_list.append(key[0])
        in_ip_dict[key[0]] = dict()
        name_list.append(key[1])

with open('test.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    reader = 0

    for ts, buf in pcap:
        reader += 1
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):   
            continue
    
        int_pro = eth.get_type(eth.type).__name__
        ip = eth.data
        tra = ip.data

        if str(type(tra)) == "<class 'bytes'>":
            continue

        tra_pro = ip.get_proto(ip.p).__name__
        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)

        if  in_ip_dict.get(src_ip) != None:
            tra_dict = in_ip_dict[src_ip]
            if tra_dict.get(tra_pro) == None:
                tra_dict[tra_pro] = dict()
                tra_dict[tra_pro]["Value"] = 0

            ip_dict = tra_dict[tra_pro]
            ip_dict["Value"] += 1
            if ip_dict.get(dst_ip) == None:
                ip_dict[dst_ip] = dict()
            

            
            if tra_pro == "TCP" or tra_pro == "UDP":
                i_p_n = str(tra.sport)
                e_p_n = str(tra.dport)
                i_p_n_dict = ip_dict[dst_ip]
                if i_p_n_dict.get(i_p_n) == None:
                    i_p_n_dict[i_p_n] = dict()
                
                e_p_n_dict = i_p_n_dict[i_p_n]
                if e_p_n_dict.get(e_p_n) == None:
                    e_p_n_dict[e_p_n] = dict()

                i_o_dict = e_p_n_dict[e_p_n]
            
            else :
                i_o_dict = ip_dict[dst_ip]

            if i_o_dict.get("out") == None:
                i_o_dict["out"] = 0
            i_o_dict["out"] += 1

        elif in_ip_dict.get(dst_ip) != None:
            tra_dict = in_ip_dict[dst_ip]
            if tra_dict.get(tra_pro) == None:
                tra_dict[tra_pro] = dict()
                tra_dict[tra_pro]["Value"] = 0

            ip_dict = tra_dict[tra_pro]
            ip_dict["Value"] += 1
            if ip_dict.get(src_ip) == None:
                ip_dict[src_ip] = dict()

            if tra_pro == "TCP" or tra_pro == "UDP":
                i_p_n = str(tra.dport)
                e_p_n = str(tra.sport)
                i_p_n_dict = ip_dict[src_ip]
                if i_p_n_dict.get(i_p_n) == None:
                    i_p_n_dict[i_p_n] = dict()
                
                e_p_n_dict = i_p_n_dict[i_p_n]
                if e_p_n_dict.get(e_p_n) == None:
                    e_p_n_dict[e_p_n] = dict()

                i_o_dict = e_p_n_dict[e_p_n]
            
            else:
                i_o_dict = ip_dict[src_ip]
            
            if i_o_dict.get("in") == None:
                    i_o_dict["in"] = 0

            i_o_dict["in"] += 1
            
for i in range(len(name_list)):
    csv_name = 'csvfolde/' + name_list[i] + '.csv'

    with open(csv_name, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        in_list = []
        in_list.append(property_ip_list[i])
        in_dic = in_ip_dict.get(property_ip_list[i])
        write_in(writer, in_dic, in_list)




