import numpy as np
import matplotlib.pyplot as plt
from scipy.fftpack import fft, ifft, fftfreq
import pandas as pd

# Import csv file
# df = pd.read_csv('minzhao.csv', index_col=['TIME'], parse_dates=['TIME'])
# print(df.head())



# plot data
#plt.figure(figsize=(12,4))
#df.plot(linestyle = '', marker = '*', color='r')
#plt.savefig('rsam_2016_2017_snippetforfft.jpg')
#plt.show()

# FFT

import packet_rate_fft


#number of sample points
N = 62
# frequency of signal (in second)
T = 1
# create x-axis for time length of signal
x = np.linspace(0, N*T, N)
# create array that corresponds to values in signal
# y = df
# perform FFT on signal
fq = packet_rate_fft.packet_frequency("dataset/webproxy/library.csv")
yf = fft(fq)
# create new x-axis: frequency from signal
xf = fftfreq(N, T)[:N//2]
# plot results
plt.stem(xf, 2.0/N*np.abs(yf[0:N//2]), label = 'signal')
plt.grid()
plt.xlabel('Frequency (Hz)')
plt.ylabel(r'Amplitude')
plt.legend(loc=1)
plt.savefig('packet_fft_library.jpg')
plt.show()


"""
fq = packet_rate_fft.packet_frequency("dataset/ns1.csv")
print(fq)
yf = fft(fq)
N = len(yf)
n = np.arange(N)
T = N/10
freq = n/T

plt.figure(figsize = (12, 6))
plt.subplot(121)

plt.stem(freq, np.abs(yf), linefmt='b', markerfmt=" ", basefmt="-b")
plt.xlabel('Freq(Hz)')
plt.ylabel("Amplitude")
plt.xlim(0, 10)
plt.savefig('packet_fft_desktop_dis.jpg')
"""