from os import execv
from numpy import append, int_
import pdb

class IpStat:
    GLOBAL_TRAFFIC_KEYS = ["total incoming traffic by packet", "total incoming traffic by byte", "total outgoing traffic by packet", "total outgoing traffic by byte"]
    HOST_TRAFFIC_KEYS = ["#incoming packet", "incoming traffic in bytes", "#outgoing packet", "outgoing traffic in bytes"] 
    HOST_SPC_KEYS = ["external IPs", "internal ports", "external ports", "protocols"]
    def __init__(self, target_IPs, start, end) -> None:
        self.start_time = start
        self.end_time = end
        self.target_IPs = target_IPs
        self.local_stat = {}
        for key in self.GLOBAL_TRAFFIC_KEYS:
            self.local_stat[key] = 0
        # self.local_stat["total incoming traffic by packet"] = 0
        # self.local_stat["total incoming traffic by byte"] = 0
        # self.local_stat["total outgoing traffic by packet"] = 0
        # self.local_stat["total outgoing traffic by byte"] = 0

    def __add__(self, other):
        # time check
        if other.end_time == self.start_time:
            result = IpStat(self.target_IPs, other.start_time, self.end_time)
        elif other.start_time == self.end_time:
            result = IpStat(self.target_IPs, self.start_time, other.end_time)
        else:
            raise Exception("only adjacent stats can be added")

        # for key in self.GLOBAL_TRAFFIC_KEYS:
        #     result.local_stat[key] = self.local_stat[key] + other.local_stat[key]
        # result.local_stat["total incoming traffic by packet"] = self.local_stat["total incoming traffic by packet"] + other.local_stat["total incoming traffic by packet"]
        # result.local_stat["total incoming traffic by byte"] = self.local_stat["total incoming traffic by byte"] + other.local_stat["total incoming traffic by byte"]
        # result.local_stat["total outgoing traffic by packet"] = self.local_stat["total outgoing traffic by packet"] + other.local_stat["total outgoing traffic by packet"]
        # result.local_stat["total outgoing traffic by byte"] = self.local_stat["total outgoing traffic by byte"] + other.local_stat["total outgoing traffic by byte"]

        # do a deep copy
        for key, value in self.local_stat.items():
                result.local_stat[key] = value

        for ip, ip_stat in other.local_stat.items():
            # global traffic stat
            if ip in self.GLOBAL_TRAFFIC_KEYS:
                result.local_stat[ip] += other.local_stat[ip]
                continue
            # new entry
            if result.local_stat.get(ip) is None:
                result.local_stat[ip] = ip_stat
            # existing entry, merge
            else:
                # merge traffic stats
                for key in self.HOST_TRAFFIC_KEYS:
                    result.local_stat[ip][key] += ip_stat[key]
                # result.local_stat[ip]["#incoming packet"] += other.local_stat[ip]["#incoming packet"]
                # result.local_stat[ip]["incoming traffic in bytes"] += other.local_stat[ip]["incoming traffic in bytes"]
                # result.local_stat[ip]["#outgoing packet"] += other.local_stat[ip]["#outgoing packet"]
                # result.local_stat[ip]["outgoing traffic in bytes"] += other.local_stat[ip]["outgoing traffic in bytes"]

                for ext_IP, ext_IP_stat in ip_stat["external IPs"].items():
                    if result.local_stat[ip]["external IPs"].get(ext_IP) is None:
                        result.local_stat[ip]["external IPs"][ext_IP] = ext_IP_stat
                    else:
                        for key in self.HOST_TRAFFIC_KEYS:
                            result.local_stat[ip]["external IPs"][ext_IP][key] += ext_IP_stat[key]
                
                for int_port, int_port_stat in ip_stat["internal ports"].items():
                    if result.local_stat[ip]["internal ports"].get(int_port) is None:
                        result.local_stat[ip]["internal ports"][int_port] = int_port_stat
                    else:
                        for key in ["#packet", "traffic in bytes"]:
                            result.local_stat[ip]["internal ports"][int_port][key] += int_port_stat[key]

                        # result.local_stat[ip]["external IPs"][ext_IP]["#incoming packet"] += other.local_stat[ip]["external IPs"][ext_IP]["#incoming packet"]
                        # result.local_stat[ip]["external IPs"][ext_IP]["incoming traffic in bytes"] += other.local_stat[ip]["external IPs"][ext_IP]["incoming traffic in bytes"]
                        # result.local_stat[ip]["external IPs"][ext_IP]["#outgoing packet"] += other.local_stat[ip]["external IPs"][ext_IP]["#outgoing packet"]
                        # result.local_stat[ip]["external IPs"][ext_IP]["outgoing traffic in bytes"] += other.local_stat[ip]["external IPs"][ext_IP]["outgoing traffic in bytes"]

                for ext_port, ext_port_stat in ip_stat["external ports"].items():
                    if result.local_stat[ip]["external ports"].get(ext_port) is None:
                        result.local_stat[ip]["external ports"][ext_port] = ext_port_stat
                    else:
                        for key in ["#packet", "traffic in bytes"]:
                            result.local_stat[ip]["external ports"][ext_port][key] += ext_port_stat[key]


                for proto, proto_stat in ip_stat["protocols"].items():
                    if result.local_stat[ip]["protocols"].get(proto) is None:
                        result.local_stat[ip]["protocols"][proto] = proto_stat
                    else:
                        for key in ["#packet", "traffic in bytes"]:
                            result.local_stat[ip]["protocols"][proto][key] += proto_stat[key]
        return result


    def __sub__(self, other):

        # time check
        if other.start_time == self.start_time:
            result = IpStat(self.target_IPs, other.end_time, self.end_time)
        elif other.end_time == self.end_time:
            result = IpStat(self.target_IPs, self.start_time, other.start_time)
        else:
            raise Exception("only head or tail of the stat can be cut")

        # do a deep copy
        for ip, ip_stat in self.local_stat.items():
            result.local_stat[ip] = ip_stat

        # for key in self.GLOBAL_TRAFFIC_KEYS:
        #     result.local_stat[key] = self.local_stat[key] - other.local_stat[key]
        # result.local_stat["total incoming traffic by packet"] = self.local_stat["total incoming traffic by packet"] + other.local_stat["total incoming traffic by packet"]
        # result.local_stat["total incoming traffic by byte"] = self.local_stat["total incoming traffic by byte"] + other.local_stat["total incoming traffic by byte"]
        # result.local_stat["total outgoing traffic by packet"] = self.local_stat["total outgoing traffic by packet"] + other.local_stat["total outgoing traffic by packet"]
        # result.local_stat["total outgoing traffic by byte"] = self.local_stat["total outgoing traffic by byte"] + other.local_stat["total outgoing traffic by byte"]

        

        for ip, ip_stat in other.local_stat.items():
            # found the entry in
            if not result.local_stat.get(ip):
                raise Exception("something went wrong")

            if ip in self.GLOBAL_TRAFFIC_KEYS:
                result.local_stat[ip] -= other.local_stat[ip]
                continue

            # existing entry, merge
            else:
                # merge traffic stats
                for key in self.HOST_TRAFFIC_KEYS:

                    result.local_stat[ip][key] -= other.local_stat[ip][key]
                # result.local_stat[ip]["#incoming packet"] += other.local_stat[ip]["#incoming packet"]
                # result.local_stat[ip]["incoming traffic in bytes"] += other.local_stat[ip]["incoming traffic in bytes"]
                # result.local_stat[ip]["#outgoing packet"] += other.local_stat[ip]["#outgoing packet"]
                # result.local_stat[ip]["outgoing traffic in bytes"] += other.local_stat[ip]["outgoing traffic in bytes"]

                for ext_IP, ext_IP_stat in ip_stat["external IPs"].items():
                    if not result.local_stat[ip]["external IPs"].get(ext_IP):
                        pdb.set_trace()
                        raise Exception("something went wrong")
                    else:
                        for key in self.HOST_TRAFFIC_KEYS:
                            result.local_stat[ip]["external IPs"][ext_IP][key] -= other.local_stat[ip]["external IPs"][ext_IP][key]
                
                for int_port, int_port_stat in ip_stat["internal ports"].items():
                    if not result.local_stat[ip]["internal ports"].get(int_port):
                        raise Exception("something went wrong")
                    else:
                        for key in ["#packet", "traffic in bytes"]:
                            result.local_stat[ip]["internal ports"][int_port][key] -= other.local_stat[ip]["internal ports"][int_port][key]

                        # result.local_stat[ip]["external IPs"][ext_IP]["#incoming packet"] += other.local_stat[ip]["external IPs"][ext_IP]["#incoming packet"]
                        # result.local_stat[ip]["external IPs"][ext_IP]["incoming traffic in bytes"] += other.local_stat[ip]["external IPs"][ext_IP]["incoming traffic in bytes"]
                        # result.local_stat[ip]["external IPs"][ext_IP]["#outgoing packet"] += other.local_stat[ip]["external IPs"][ext_IP]["#outgoing packet"]
                        # result.local_stat[ip]["external IPs"][ext_IP]["outgoing traffic in bytes"] += other.local_stat[ip]["external IPs"][ext_IP]["outgoing traffic in bytes"]

                for ext_port, ext_port_stat in ip_stat["external ports"].items():
                    if not result.local_stat[ip]["external ports"].get(ext_port):
                        raise Exception("something went wrong")
                    else:
                        for key in ["#packet", "traffic in bytes"]:
                            result.local_stat[ip]["external ports"][ext_port][key] -= other.local_stat[ip]["external ports"][ext_port][key]


                for proto, proto_stat in ip_stat["protocols"].items():
                    if not result.local_stat[ip]["protocols"].get(proto):
                        raise Exception("something went wrong")
                    else:
                        for key in ["#packet", "traffic in bytes"]:
                            result.local_stat[ip]["protocols"][proto][key] -= other.local_stat[ip]["protocols"][proto][key]
        return result


    def update_stat(self, size, eth_src, eth_dst, ip_src, ip_dst, proto, port_src, port_dst):
        
        for ip in self.target_IPs:

            if (ip_src == ip or ip_dst == ip) and self.local_stat.get(ip) == None:
                self.local_stat[ip] = {}
                
                for key in self.HOST_TRAFFIC_KEYS:
                    self.local_stat[ip][key] = 0

                # self.local_stat[ip]["incoming traffic"] = {}
                # self.local_stat[ip]["# incoming packet"] = 0
                # self.local_stat[ip]["incoming traffic"]["traffic in bytes"] = 0
                # self.local_stat[ip]["outgoing traffic"] = {}
                # self.local_stat[ip]["outgoing traffic"]["#packet"] = 0
                # self.local_stat[ip]["outgoing traffic"]["traffic in bytes"] = 0

                for key in self.HOST_SPC_KEYS:
                    self.local_stat[ip][key] = {}

                # self.local_stat[ip]["external IPs"] = {}
                # self.local_stat[ip]["internal ports"] = {}
                # self.local_stat[ip]["external ports"] = {}
                # self.local_stat[ip]["protocols"] = {}


            if ip_src == ip:
                # outgoing packet
                self.local_stat["total outgoing traffic by packet"] += 1
                self.local_stat["total outgoing traffic by byte"] += size
                
                self.local_stat[ip]["#outgoing packet"] += 1
                self.local_stat[ip]["outgoing traffic in bytes"] += size
                


                if self.local_stat[ip]["external IPs"].get(ip_dst) == None:
                    self.local_stat[ip]["external IPs"][ip_dst] = {}

                    for key in self.HOST_TRAFFIC_KEYS:
                        self.local_stat[ip]["external IPs"][ip_dst][key] = 0
                    # self.local_stat[ip]["external IPs"][ip_dst]["#incoming packet"] = 0
                    # self.local_stat[ip]["external IPs"][ip_dst]["incoming traffic in bytes"] = 0
                    # self.local_stat[ip]["external IPs"][ip_dst]["#outgoing packet"] = 0
                    # self.local_stat[ip]["external IPs"][ip_dst]["outgoing traffic in bytes"] = 0
                
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

                self.local_stat[ip]["#incoming packet"] += 1
                self.local_stat[ip]["incoming traffic in bytes"] += size
                
                if self.local_stat[ip]["external IPs"].get(ip_src) == None:
                    self.local_stat[ip]["external IPs"][ip_src] = {}

                    for key in self.HOST_TRAFFIC_KEYS:
                        self.local_stat[ip]["external IPs"][ip_src][key] = 0
                    
                    # self.local_stat[ip]["external IPs"][ip_src]["#incoming packet"] = 0
                    # self.local_stat[ip]["external IPs"][ip_src]["incoming traffic in bytes"] = 0
                    # self.local_stat[ip]["external IPs"][ip_src]["#outgoing packet"] = 0
                    # self.local_stat[ip]["external IPs"][ip_src]["outgoing traffic in bytes"] = 0

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
    def analyze_features(self, target_IPs, target_IP_types):
        OUTPUT_HEADER = ["IP", "host type", "start time", "end time", "#incoming packet%", "#outgoing packet%", "incoming traffic/byte%", "outgoing traffic/byte%", "avg incoming packet size", "avg outgoing packet size", \
        "top external IP%(pkt)", "top external IP%(size)", \
        "number of external IP", "top internal port(pkt)","top internal port(pkt)%", "top internal port(byte)", \
        "top internal port%(byte)","top external port(pkt)","top external port(pkt)%", "top external port(byte)","top external port(byte)%",\
        "top proto(pkt)", "top proto(pkt)%", "top proto(byte)", "top proto(byte)%"]

        out_list = []
        #out_list.append(OUTPUT_HEADER)
        i = 0
        for ip in target_IPs:
            out_list.append([])
            out_list[i].append(ip)
            out_list[i].append(target_IP_types[ip])
            out_list[i].append(self.start_time)
            out_list[i].append(self.end_time)
            
            # create empty row
            if self.local_stat.get(ip) == None:
                for k in range(4, len(OUTPUT_HEADER)):
                    if (OUTPUT_HEADER[k] == "top proto(pkt)" or OUTPUT_HEADER[k] == "top proto(byte)"):
                        out_list[i].append("/")
                    else:
                        out_list[i].append(0)
                i += 1 
                continue
            

            # start to generate IP specific start
            
            

        # packet rate(incoming/outgoing/bidirection)
            in_pkt = self.local_stat[ip]["#incoming packet"]
            out_pkt = self.local_stat[ip]["#outgoing packet"]
            total_pkt = in_pkt + out_pkt
            in_size = self.local_stat[ip]["incoming traffic in bytes"]
            out_size = self.local_stat[ip]["outgoing traffic in bytes"]
            total_size = in_size + out_size
            if total_pkt > 0:
                out_list[i].append(in_pkt/total_pkt)
                out_list[i].append(out_pkt/total_pkt)
            else:
                out_list[i].append(0)
                out_list[i].append(0)
            
            if total_size > 0:
                out_list[i].append(in_size/total_size)
                out_list[i].append(out_size/total_size)
            else:
                out_list[i].append(0)
                out_list[i].append(0)

        # average packet size(incoming/outgoing)
            if out_list[i][-2] > 0:
                avg_in_size = self.local_stat[ip]["incoming traffic in bytes"]\
                            /self.local_stat[ip]["#incoming packet"]
            else:
                avg_in_size = 0

            if out_list[i][-1] > 0:
                avg_out_size = self.local_stat[ip]["outgoing traffic in bytes"]\
                            /self.local_stat[ip]["#outgoing packet"]
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
        for key in self.GLOBAL_TRAFFIC_KEYS:
            self.local_stat[key] = 0

        # self.local_stat["total incoming traffic by packet"] = 0
        # self.local_stat["total incoming traffic by byte"] = 0
        # self.local_stat["total outgoing traffic by packet"] = 0
        # self.local_stat["total outgoing traffic by byte"] = 0
        
