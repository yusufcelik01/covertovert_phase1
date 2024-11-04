import scapy.all as scapy

# Implement your ICMP sender here
#pkt = scapy.Ether(dst="02:42:ac:12:00:03") / scapy.IP(dst="172.18.0.3", ttl=1) / scapy.ICMP() / "DGCFAD"
##scapy.send(pkt)
##scapy.sendp(pkt, iface="eth0")
#scapy.sendp(pkt, iface="eth0")


pkt = scapy.Ether(dst="02:42:ac:12:00:03") / scapy.IP(dst="127.0.0.1", ttl=1) / scapy.ICMP() / "DGCFAD"
scapy.sendp(pkt, iface="lo")
