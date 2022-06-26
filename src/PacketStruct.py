from typing import Literal


class PacketStruct:
    p_id : int
    p_time : int
    p_size : int
    p_eth_src : str
    p_eth_dst : str
    p_ip_src : str
    p_ip_dst : str
    p_proto : Literal[6]
    p_port_src : int
    p_port_dst : int