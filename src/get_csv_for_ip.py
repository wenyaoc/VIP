import csv 
import pandas as pd

header = ['Packet ID', 'TIME', 'Size', 'eth.src', 'eth.dst', 'IP.src', 'IP.dst', 'IP.proto', 'port.src', 'port.dst']
devIP = "149.171.0.34"
data = pd.read_csv("21Feb.csv")

with open('/home/wenyao/VIP/hosproxy_21Feb.csv', 'w', encoding='UTF8', newline='') as f:
    writer = csv.writer(f)
    # write the header
    writer.writerow(header)
    for index, row in data.iterrows():
        if row['IP.src'] == devIP or row['IP.dst'] == devIP:
            print(row['TIME'])
            writer.writerow(row)
