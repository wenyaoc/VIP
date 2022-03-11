import csv 
import os
import pandas as pd

def getAvgSize(total, count):
    if count == 0:
        return 0
    else:
        return int(total/count)  


def generateFlow(file): 
    Gateway = "14:cc:20:51:33:ea"
    devMAC = "44:65:0d:56:cc:d3"
    header = ['ID',  
            'DNS.out.size', 'DNS.out.rate', 
            'DNS.in.size', 'DNS.in.rate',
            'NTP.out.size', 'NTP.out.rate',
            'NTP.in.size', 'NTP.in.rate', 
            'SSDP.out.size', 'SSDP.out.rate', 
            'remote.out.size', 'remote.out.rate',
            'remote.in.size', 'remote.in.rate', 
            'local.in.size', 'local.in.rate']
    currTime = 0
    DNS_out = 0
    DNS_in = 0
    NTP_out = 0
    NTP_in = 0
    SSDP_out = 0
    remote_out = 0
    remote_in = 0
    local_in = 0
    DNS_out_count = 0
    DNS_in_count = 0
    NTP_out_count = 0
    NTP_in_count = 0
    SSDP_out_count = 0
    remote_out_count = 0
    remote_in_count = 0
    local_in_count = 0

    start = 0
    count = 1
    addr = "/home/wenyao/dataset/" + file
    data = pd.read_csv(addr)
    # data = data.loc[(data['eth.src'] == devMAC) | (data['eth.dst'] == devMAC)]
    fileName = file[:8] + '-AmazonEcho.csv'
    print(fileName)
    with open(fileName, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        # write the header
        writer.writerow(header)

        for index, row in data.iterrows():
            #print(f"curr: {currTime}, row:{row['TIME']}")
            if row['TIME'] > currTime + 60 and start == 1:
                # print(f"time: {currTime}, DNS_out: {DNS_out}, DNS_in: {DNS_in}, NTP_out: {NTP_out}, NTP_in: {NTP_in}")
                # print(f"                  SSDP_out: {SSDP_out}, remote_out: {remote_out}, remote_in: {remote_in}, local_in: {local_in}")

                flow_data = [count, 
                            getAvgSize(DNS_out, DNS_out_count), DNS_out, 
                            getAvgSize(DNS_in, DNS_in_count), DNS_in, 
                            getAvgSize(NTP_out, NTP_out_count), NTP_out, 
                            getAvgSize(NTP_in, NTP_in_count), NTP_in, 
                            getAvgSize(SSDP_out, SSDP_out_count), SSDP_out, 
                            getAvgSize(remote_out, remote_out_count), remote_out, 
                            getAvgSize(remote_in, remote_in_count), remote_in, 
                            getAvgSize(local_in, local_in_count), local_in]
                writer.writerow(flow_data)
                count += 1
                DNS_out = 0
                DNS_in = 0
                NTP_out = 0
                NTP_in = 0
                SSDP_out = 0
                remote_out = 0
                remote_in = 0
                local_in = 0
                DNS_out_count = 0
                DNS_in_count = 0
                NTP_out_count = 0
                NTP_in_count = 0
                SSDP_out_count = 0
                remote_out_count = 0
                remote_in_count = 0
                local_in_count = 0
                currTime = row['TIME'] 

            if start == 0:
                start = 1  
                currTime = row['TIME'] 

            if row['eth.src'] == devMAC and row['port.dst'] == 53 and row['IP.proto'] == 17:
                # DNS outgoing
                DNS_out += row['Size']
                DNS_out_count += 1
            elif row['eth.dst'] == devMAC and row['port.src'] == 53 and row['IP.proto'] == 17:
                # DNS incoming
                DNS_in += row['Size']  
                DNS_in_count += 1  
            elif row['eth.src'] == devMAC and row['port.dst'] == 123 and row['IP.proto'] == 17:
                # NTP outgoing
                NTP_out += row['Size']
                NTP_out_count += 1
            elif row['eth.dst'] == devMAC and row['port.src'] == 123 and row['IP.proto'] == 17:
                # NTP incoming
                NTP_in += row['Size']  
                NTP_in_count += 1  
            elif row['eth.src'] == devMAC and row['port.dst'] == 1900 and row['IP.proto'] == 17:
                # SSDP outgoing
                SSDP_out += row['Size'] 
                SSDP_out_count += 1
            elif row['eth.src'] == devMAC and row['eth.dst'] == Gateway:
                # remote outgoing
                remote_out += row['Size']   
                remote_out_count += 1
            elif row['eth.src'] == Gateway and row['eth.dst'] == devMAC:
                # remote incoming
                remote_in += row['Size']  
                remote_in_count += 1 
            elif row['eth.dst'] == devMAC:   
                # local incoming
                local_in += row['Size'] 
                local_in_count == 1  

        flow_data = [count, 
                    getAvgSize(DNS_out, DNS_out_count), DNS_out, 
                    getAvgSize(DNS_in, DNS_in_count), DNS_in, 
                    getAvgSize(NTP_out, NTP_out_count), NTP_out, 
                    getAvgSize(NTP_in, NTP_in_count), NTP_in, 
                    getAvgSize(SSDP_out, SSDP_out_count), SSDP_out, 
                    getAvgSize(remote_out, remote_out_count), remote_out, 
                    getAvgSize(remote_in, remote_in_count), remote_in, 
                    getAvgSize(local_in, local_in_count), local_in]
        writer.writerow(flow_data)    


directory = "/home/wenyao/dataset"
for root,dirs,files in os.walk(directory):
    for file in files:
       if file.endswith(".csv"):
           generateFlow(file)
