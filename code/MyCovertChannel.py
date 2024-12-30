from CovertChannelBase import CovertChannelBase
from scapy.all import sniff
from scapy.layers import l2
from scapy import arch
from functools import partial

#TODO remove import below
import pdb

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        self.recently_sniffed_bits = ''
        self.used_bits_mask = 0xFFFFFFFF

    def ip_int2str(self, intIP):
        strBytes = []
        for i in range(4):#4 bytes
            byte = intIP & 0xFF
            intIP = intIP >> 8
            strBytes = [str(byte)] + strBytes

        strIP = '.'.join(strBytes)
        #strIP = "0.0.0.0"

        return strIP

    def ip_str2int(self, strIP):
        strBytes = strIP.split('.')
        intBytes = map(int, strBytes)

        intIP = 0
        for byte in intBytes:
            intIP = intIP << 8
            intIP = intIP | byte

        return intIP

    def extract_msg_from_ip(self, ip, mask):
        #get string ip and extract binary message
        binary_msg = ''
        int_ip = self.ip_str2int(ip) & mask

        #pdb.set_trace();
        for i in range(31, -1, -1):
            current_bit = 1 << i
            if(current_bit & mask != 0):
                if(int_ip & current_bit != 0):
                    binary_msg += '1'
                else:
                    binary_msg += '0'


        return binary_msg





    def embed_msg_to_ip(self, ip, mask, msg):
        #return the unsent part of the message and the message encoded ip
        #mask and ip must be converted to int format
        #msg must be in binary string format

        #take out the bits we will use for transmitting the message
        ip_w_msg = ip & (0xFFFFFFFF ^ mask)
        for i in range(31, -1, -1):
            if(len(msg) == 0):
                break
            current_bit = 1 << i
            if(current_bit & mask != 0):
                #print("current_bit", bin(current_bit))
                if(msg[0] == '1'):
                    ip_w_msg |= current_bit
                #else that bit is not set so do nothing we already cleared the bits
                msg = msg[1:]

        return (ip_w_msg, msg)

    def send(self, log_file_name, mask, destinationIP):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        iface_name = "eth0"
        eth0IP = arch.get_if_addr(iface_name)
        eth0MAC = arch.get_if_hwaddr(iface_name)
        sourceIP = eth0IP
        targetIP = destinationIP


        int_mask = int(mask, 16)

        #generate message
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        #create arp packet and set it's fields
        pkt = l2.Ether() / l2.ARP() / "dummy"
        pkt.dst = "FF:FF:FF:FF:FF:FF" #broadcast ARP request by setting eth broadcast address
        pkt.hwsrc = eth0MAC
        pkt.psrc= sourceIP
        pkt.pdst = targetIP
        #pkt.show()

        #pdb.set_trace();#TODO remove

        src_ip_int = self.ip_str2int(sourceIP)
        msg_embedded_ip = sourceIP
        msg = binary_message

        while len(msg) > 0:
            msg_embedded_ip, msg = self.embed_msg_to_ip(src_ip_int, int_mask, msg)
            #print("binary_syn_msg", msg)
            pkt.psrc = self.ip_int2str(msg_embedded_ip)
            #print("pkt src ip: ", pkt.psrc)
            super().send(pkt, interface = iface_name)



        
    def check_dot_char(self, mask_int, pkt):
        new_bits = self.extract_msg_from_ip(pkt.psrc, mask_int)
        self.recently_sniffed_bits += new_bits
        if len(self.recently_sniffed_bits) > 7:
            c = self.convert_eight_bits_to_character(self.recently_sniffed_bits[:8])
            self.recently_sniffed_bits = self.recently_sniffed_bits[8:]
            if c == '.':
                return True
        return False

    def receive(self, mask, destinationIP, log_file_name):
        self.recently_sniffed_bits = ''
        self.used_bits_mask = 0xFFFFFFFF
        """
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        mask_int = int(mask, 16)
        packets = sniff(filter="arp", stop_filter = partial(self.check_dot_char, mask_int))
        binary_msg = ''
        msg_str = ''
        current_char_bits = ''
        for pkt in packets:
            if pkt.pdst != destinationIP:
                continue
            current_pkt_bits = self.extract_msg_from_ip(pkt.psrc, mask_int)
            #print("I received (ip, bits): ", pkt.psrc, current_pkt_bits)
            current_char_bits += current_pkt_bits
            if(len(current_char_bits) > 7):#a char has arrived
                char_bits = current_char_bits[:8]
                c = self.convert_eight_bits_to_character(char_bits)
                current_char_bits = current_char_bits[8:]
                msg_str += c

                if c == '.':
                    break

            binary_msg += current_pkt_bits

        #self.log_message(binary_msg, log_file_name)
        self.log_message(msg_str, log_file_name)
