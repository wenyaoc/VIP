import csv 
import pandas as pd

def packet_frequency(filename):
    data = pd.read_csv(filename)

    packet_count_list = []
    packet_count = 0
    start = 0
    currTime = 0
    for index, row in data.iterrows():
        if row['TIME'] != currTime and start == 1:
            packet_count_list.append(packet_count)
            packet_count = 0
            currTime += 1

        if start == 0:
            start = 1
            currTime = row['TIME']

        packet_count += 1

    return packet_count_list

     
