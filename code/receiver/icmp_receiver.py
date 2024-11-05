import scapy.all as scapy
import time

def is_senders_packet(pkt):
    if type(pkt) == scapy.Ether:
        l3_pkt = pkt.payload
        if type(l3_pkt) == scapy.IP and l3_pkt.ttl == 1:
            ip_payload = l3_pkt.payload
            if type(ip_payload) == scapy.ICMP:
                if ip_payload.type == 8:#is icmp request
                    return True

    return False


while True:
    pkt_list = scapy.sniff(iface='eth0', count = 1)
    pkt = pkt_list[0]

    if is_senders_packet(pkt):
        pkt.show()
        break;
