# GROUP 81

## Members
- Yusuf Celik 2457703
- Yigithan Tamer 2448868

## Repository link
[https://github.com/yusufcelik01/covertovert](https://github.com/yusufcelik01/covertovert)

# ICMP SENDER

  Sends an ICMP request through the eth0 interface. Which uses receiver containers MAC address and sets IP datagrams ttl to 1. Also in the payload of the ICMP message sends a surprise guitar tuning.


# ICMP RECEIVER

- Uses scapy's sniff function to sniff eth0 interface
- Uses is\_senders\_packet: Returns true if the packet is an ICMP request with TTL=1
- Waits indefinetly in a while loop until it receives the aforementioned ICMP packet. 


