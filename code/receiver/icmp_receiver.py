import scapy.all as scapy
import time

# Implement your ICMP receiver here
def print_packet(packet):
    packet.show()

#scapy.sniff(prn=print_packet, count=2, iface="lo")
scapy.sniff(prn=print_packet, count=2, iface="eth0")
#scapy.sniff(count=2, iface="lo")

"""
dummyLoad = "EADGBE"
dummyPkt= scapy.IP() / scapy.ICMP() / dummyLoad

while True:
    ans, unans = scapy.sr(dummyPkt, verbose=False)
    for pkt in ans:
        print(pkt)
    time.sleep(1)
    """
