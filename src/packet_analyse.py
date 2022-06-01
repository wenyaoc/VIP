import csv 
import pandas as pd
import collections
import matplotlib.pyplot as plt
import itertools
import numpy as np
import datetime

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



devIP = "149.171.99.123"
data = pd.read_csv("./data/myunsw_23Mar.csv")
#header = ['Packet ID', 'TIME', 'Size', 'eth.src', 'eth.dst', 
#          'IP.src', 'IP.dst', 'IP.proto', 'port.src', 'port.dst']

total_size_in = 0
packet_in = 0
total_size_out = 0
packet_out = 0
ip_external_in = []
ip_external_out = []
port_in = []
port_out = []
currTime = data.iloc[0]['TIME']
for index, row in data.iterrows():
    if (row['TIME'] >= (currTime + 60)):
        ip_external_in_occurrences = collections.Counter(ip_external_in)
        ip_external_out_occurrences = collections.Counter(ip_external_out)
        port_in_occurrences = collections.Counter(port_in)
        port_out_occurrences = collections.Counter(port_out)

        print(f"time {datetime.datetime.fromtimestamp(currTime).strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"total packet number (in): {packet_in}")
        print(f"Avg size (in): {total_size_in/packet_in}")

        print(f"total packet number (out): {packet_out}")
        print(f"Avg size (out): {total_size_out/packet_out}")

        print(f"# incoming IP: {len(ip_external_in_occurrences)}")
        print(f"# outgoing IP: {len(ip_external_out_occurrences)}")

        print("port_in_occurrences:")
        print(port_in_occurrences)
        print("port_out_occurrences:")
        print(port_out_occurrences)

        plot_piechart(ip_external_in_occurrences, f'./output/myunsw23_ip_{currTime}_in.jpg', 700)
        plot_piechart(ip_external_out_occurrences, f'./output/myunsw23_ip_{currTime}_out.jpg', 700)
        #plot_piechart(port_in_occurrences, f'myunsw23_port_in.jpg', 0)
        #plot_piechart(port_out_occurrences, f'myunsw23_port_out.jpg', 0)


        total_size_in = 0
        packet_in = 0
        total_size_out = 0
        packet_out = 0
        ip_external_in = []
        ip_external_out = []
        port_in = []
        port_out = []
        currTime = row['TIME']


    else:
        if row['IP.src'] == devIP:       
            ip_external_out.append(row['IP.dst'])
            port_out.append(row['port.src'])
            total_size_out += row['Size']
            packet_out += 1

        else:
            ip_external_in.append(row['IP.src'])
            port_in.append(row['port.dst'])
            total_size_in += row['Size']
            packet_in += 1


print(f"time {datetime.datetime.fromtimestamp(currTime).strftime('%Y-%m-%d %H:%M:%S')}")

print(f"total packet number (in): {packet_in}")
print(f"Avg size (in): {total_size_in/packet_in}")

print(f"total packet number (out): {packet_out}")
print(f"Avg size (out): {total_size_out/packet_out}")

print(f"# incoming IP: {len(ip_external_in_occurrences)}")
print(f"# outgoing IP: {len(ip_external_out_occurrences)}")

print("port_in_occurrences:")
print(port_in_occurrences)
print("port_out_occurrences:")
print(port_out_occurrences)