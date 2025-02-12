
import pyshark
capture = pyshark.FileCapture('testdump.pcap')
for packet in capture:
    print(packet)