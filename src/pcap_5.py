import dpkt
import socket
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

def add_pro(i, int_pro, tra_pro, int_p, int_u, tra_p, tra_u):
    if int_pro not in int_p[i]:
        int_p[i].append(int_pro)
        int_u[i].append(0)
    j = int_p[i].index(int_pro)
    int_u[i][j] += 1

    if tra_pro not in tra_p[i]:
        tra_p[i].append(tra_pro)
        tra_u[i].append(0)
    j = tra_p[i].index(tra_pro)
    tra_u[i][j] += 1

def input_port(s_p_n, d_p_n, in_p, in_u, ex_p, ex_u, i) :
    if s_p_n not in in_p[i]:
        in_p[i].append(s_p_n)
        in_u[i].append(0)
    j = in_p[i].index(s_p_n)
    in_u[i][j] += 1

    if d_p_n not in ex_p[i]:
        ex_p[i].append(d_p_n)
        ex_u[i].append(0)
    j = ex_p[i].index(d_p_n)
    ex_u[i][j] += 1

property_ip_list = []
name_list =[]
in_int_pro = []
in_int_use = []
in_tra_pro = []
in_tra_use = []
in_tcp_flags = []
in_tcp_fl_use = []
ex_int_pro = []
ex_int_use = []
ex_tra_pro = []
ex_tra_use = []
ex_tcp_flags = []
ex_tcp_fl_use = []
in_tcp_port = []
in_tcp_use = []
in_udp_port = []
in_udp_use = []
ex_tcp_port = []
ex_tcp_use = []
ex_udp_port = []
ex_udp_use = []

with open('ips.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        key = line.split( )
        property_ip_list.append(key[0])
        name_list.append(key[1])
        in_int_pro.append([])
        in_int_use.append([])
        in_tra_pro.append([])
        in_tra_use.append([])
        in_tcp_flags.append([])
        in_tcp_fl_use.append([])
        ex_int_pro.append([])
        ex_int_use.append([])
        ex_tra_pro.append([])
        ex_tra_use.append([])
        ex_tcp_flags.append([])
        ex_tcp_fl_use.append([])
        in_tcp_port.append([])
        in_tcp_use.append([])
        in_udp_port.append([])
        in_udp_use.append([])
        ex_tcp_port.append([])
        ex_tcp_use.append([])
        ex_udp_port.append([])
        ex_udp_use.append([])


with open('test.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    reader = 0

    for ts, buf in pcap:
        reader += 1
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            if src_ip in property_ip_list:
                i = property_ip_list.index(src_ip)
                if int_pro not in ex_int_pro[i]:
                    ex_int_pro[i].append(int_pro)
                    ex_int_use[i].append(0)
                j = ex_int_pro[i].index(int_pro)
                ex_int_use[i][j] += 1
            elif dst_ip in property_ip_list:
                i = property_ip_list.index(dst_ip)
                if int_pro not in in_int_pro[i]:
                    in_int_pro[i].append(int_pro)
                    in_int_use[i].append(0)
                j = in_int_pro[i].index(int_pro)
                in_int_use[i][j] += 1
            continue
    
        int_pro = eth.get_type(eth.type).__name__
        ip = eth.data
        tra = ip.data

        if str(type(tra)) == "<class 'bytes'>":
            continue

        tra_pro = ip.get_proto(ip.p).__name__
        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)

        if src_ip in property_ip_list:

            i = property_ip_list.index(src_ip)
            add_pro(i, int_pro, tra_pro,\
                    ex_int_pro, ex_int_use, ex_tra_pro, ex_tra_use)

    
            if 'TCP' == tra_pro:
                input_port(tra.sport, tra.dport,\
                        in_tcp_port, in_tcp_use, \
                        ex_tcp_port, ex_tcp_use, i)
                tcp_f = str(tra.flags)
                if tcp_f not in ex_tcp_flags[i]:
                    ex_tcp_flags[i].append(tcp_f)
                    ex_tcp_fl_use[i].append(0)
                j = ex_tcp_flags[i].index(tcp_f)
                ex_tcp_fl_use[i][j] += 1
            
            if 'UDP' == tra_pro:
                input_port(tra.sport, tra.dport,\
                        in_udp_port, in_udp_use, \
                        ex_udp_port, ex_udp_use, i)
            

        elif dst_ip in property_ip_list:

            i = property_ip_list.index(dst_ip)
            add_pro(i, int_pro, tra_pro,\
                    in_int_pro, in_int_use, in_tra_pro, in_tra_use)

            if 'TCP' == tra_pro:
                input_port(tra.dport, tra.sport,\
                        in_tcp_port, in_tcp_use, \
                        ex_tcp_port, ex_tcp_use, i)
                tcp_f = str(tra.flags)
                if tcp_f not in in_tcp_flags[i]:
                    in_tcp_flags[i].append(tcp_f)
                    in_tcp_fl_use[i].append(0)
                j = in_tcp_flags[i].index(tcp_f)
                in_tcp_fl_use[i][j] += 1
            

            if 'UDP' == tra_pro:
                input_port(tra.dport, tra.sport,\
                        in_udp_port, in_udp_use, \
                        ex_udp_port, ex_udp_use, i) 


with open('output2.txt', 'w', encoding = 'utf-8') as f:
    for i in range(len(property_ip_list)):
            write_out = name_list[i] + ': ip:' + property_ip_list[i] + '\n'
            f.write(write_out)

            f.write('Incoming protocols_internet:\n')
            for j in range(len(in_int_pro[i])):
                num = in_int_use[i][j]
                write_out = in_int_pro[i][j] + ' : ' + str(num) + '\n'
                f.write(write_out)

            f.write('Incoming protocols_transport\n')
            for j in range(len(in_tra_pro[i])):
                num = in_tra_use[i][j]
                write_out = in_tra_pro[i][j] + ' : ' + str(num) + '\n'
                f.write(write_out)

            f.write('Incoming TCP_flags\n')
            for j in range(len(in_tcp_flags[i])):
                num = in_tcp_fl_use[i][j]
                write_out = in_tcp_flags[i][j] + ' : ' + str(num) + '\n'
                f.write(write_out)

            f.write('Outgoing protocols_internet\n')
            for j in range(len(ex_int_pro[i])):
                num = ex_int_use[i][j]
                write_out = ex_int_pro[i][j] + ' : ' + str(num) + '\n'
                f.write(write_out)

            f.write('Outgoing protocols_transport\n')
            for j in range(len(ex_tra_pro[i])):
                num = ex_tra_use[i][j]
                write_out = ex_tra_pro[i][j] + ' : ' + str(num) + '\n'
                print(write_out)

            f.write('Outgoing TCP_flags\n')
            for j in range(len(ex_tcp_flags[i])):
                num = ex_tcp_fl_use[i][j]
                write_out = ex_tcp_flags[i][j] + ' : ' + str(num) + '\n'
                f.write(write_out)
            
            if 'TCP' in in_tra_pro[i] or 'TCP' in ex_tra_pro[i]:
                j = in_tcp_use[i].index(max(in_tcp_use[i]))
                write_out = 'most use tcp inter_port:' + str(in_tcp_port[i][j]) + '\n'
                f.write(write_out)
                
                k = ex_tcp_use[i].index(max(ex_tcp_use[i]))
                write_out = 'most use tcp exter_port:' + str(ex_tcp_port[i][k]) + '\n'
                f.write(write_out)

            if 'UDP' in in_tra_pro[i] or 'UDP' in ex_tra_pro[i]:
                j = in_udp_use[i].index(max(in_udp_use[i]))
                write_out = 'most use udp inter_port:' + str(in_udp_port[i][j]) + '\n'
                f.write(write_out)

                k = ex_udp_use[i].index(max(ex_udp_use[i]))
                write_out = 'most use udp exter_port:' + str(ex_udp_port[i][k]) + '\n'
                f.write(write_out)


            f.write('=======================================\n')