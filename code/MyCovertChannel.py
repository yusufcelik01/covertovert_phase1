from CovertChannelBase import CovertChannelBase
from scapy.all import sniff
from scapy.layers import l2
from scapy import arch
from functools import partial

#TODO remove import below
import pdb

class MyCovertChannel(CovertChannelBase):
    """
    - Contains the sender, receiver and all helper functions for the covert channel
    - Core functions are: send and receive 
    """
    def __init__(self):
        self.recently_sniffed_bits = ''
        self.used_bits_mask = 0xFFFFFFFF

    def ip_int2str(self, intIP):
        """
        - takes an IPv4 IP in scapy's string format and converts it to an 32 bit integer
        - returned number is not very human readable but makes bit operations on IP possible
        - example: takes \'172.0.168.231\' and returns 2885724391"
        """
        strBytes = []
        for i in range(4):#4 bytes
            byte = intIP & 0xFF
            intIP = intIP >> 8
            strBytes = [str(byte)] + strBytes

        strIP = '.'.join(strBytes)
        #strIP = "0.0.0.0"

        return strIP

    def ip_str2int(self, strIP):
        """
        - takes an IPv4 IP in raw integer type and converts it to scapy's string IP format 
        - example: takes 2885724391 and returns  \'172.0.168.231\'"
        """
        strBytes = strIP.split('.')
        intBytes = map(int, strBytes)

        intIP = 0
        for byte in intBytes:
            intIP = intIP << 8
            intIP = intIP | byte

        return intIP

    def extract_msg_from_ip(self, ip, mask):
        """
        - gets a ip and extracts the bits given in the mask
        - ip must be in scapy's string ip format where as mask must be integer
        """
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
        """
        - return the message encoded ip and the unsent part of the message
        - mask and ip must be converted to int format
        - msg must be in binary string format
        """

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

    def encode_msg(self, msg, inv_bits):
        """
        - Takes a message in binary string format and inverts it's bits according to given encoding mask
        - The bits with value '1' in mask (inv_bits argument) are inverted in msg
        - If the msg is longer than the mask as it should be in most cases the mask is repeated from the start 
        """
        encoded_msg = ''
        inv_len = len(inv_bits)

        for i, c in enumerate(msg):
            if inv_bits[i % inv_len] == '1':
                if c == '1':
                    encoded_msg += '0'
                else:
                    encoded_msg += '1'
            else:
                encoded_msg += c

        return encoded_msg


    def send(self, log_file_name, mask, enc_mask, destinationIP):
        """
        Main function of covert channel sender. Performs the actions in the given order below:
        - Creates a random binary message and logs it
        - Encodes the message using the enc_mask 
        - Creates a generic ARP packet with host machines information to manipulate later
        - Sends packets by embedding the encoded message into Generic packet

        In these steps only the source IP field in arp is manipulated to transger bits according to given masks
        Using a mask with more 1 bits would create a channel with higher capacity but also channel may become more suspicious
        """

        #Get host machines info
        iface_name = "eth0"
        eth0IP = arch.get_if_addr(iface_name)
        eth0MAC = arch.get_if_hwaddr(iface_name)
        sourceIP = eth0IP
        targetIP = destinationIP


        int_mask = int(mask, 16)
        int_enc_mask = int(enc_mask, 16)

        #generate message
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        #encode message
        encoded_bin_msg = self.encode_msg(binary_message, enc_mask)

        #create generic arp packet and set it's fields
        pkt = l2.Ether() / l2.ARP() / self.generate_random_message()
        pkt.dst = "FF:FF:FF:FF:FF:FF" #broadcast ARP request by setting eth broadcast address
        pkt.hwsrc = eth0MAC
        pkt.psrc= sourceIP
        pkt.pdst = targetIP

        src_ip_int = self.ip_str2int(sourceIP)
        msg_embedded_ip = sourceIP
        msg = encoded_bin_msg

        while len(msg) > 0:
            msg_embedded_ip, msg = self.embed_msg_to_ip(src_ip_int, int_mask, msg)
            pkt.psrc = self.ip_int2str(msg_embedded_ip)
            super().send(pkt, interface = iface_name)



        
    def check_dot_char(self, mask_int, pkt):
        """
        This a receiver helper function. In order to stop the packet sniffing we must provide a function to scapy's sniff function that will report when a dot is received. This function keeps track of the bits only for the last 8 characters and temporarily decodes and decides if the dot character is received.
        """
        inv_len = len(self.inv_mask)
        new_bits = self.extract_msg_from_ip(pkt.psrc, mask_int)
        for c in new_bits:
            if self.inv_mask[self.next_bit_to_decode % inv_len] == '1':
                if c == '1':
                    self.recently_sniffed_bits += '0'
                else:
                    self.recently_sniffed_bits += '1'

            else:
                self.recently_sniffed_bits += c
            self.next_bit_to_decode += 1



        if len(self.recently_sniffed_bits) > 7:
            c = self.convert_eight_bits_to_character(self.recently_sniffed_bits[:8])
            self.recently_sniffed_bits = self.recently_sniffed_bits[8:]
            if c == '.':
                return True
            else:
                print(c, end='')
        return False

    def receive(self, mask, destinationIP, enc_mask, log_file_name):
        """
        Core function of the covert channel's receiver using helper function \'check_dot_char\' sniffs ARP packets until the dot character is receiver. Then decodes the packets with expected destination IP. This destion IP is a parameter and is a form of secret handshake between sender and the receiver
        """
        self.recently_sniffed_bits = ''
        self.inv_mask = enc_mask
        self.next_bit_to_decode = 0
        self.used_bits_mask = 0xFFFFFFFF
        mask_int = int(mask, 16)

        #start sniffing
        packets = sniff(filter="arp", stop_filter = partial(self.check_dot_char, mask_int))
        binary_msg = ''
        msg_str = ''
        current_char_bits = ''
        bit_to_decode = 0
        inv_len = len(enc_mask)

        #decode the message until there are no packets are left or the dot character is received
        for pkt in packets:
            if pkt.pdst != destinationIP:
                continue
            current_pkt_bits = self.extract_msg_from_ip(pkt.psrc, mask_int)
            for c in current_pkt_bits:
                if self.inv_mask[bit_to_decode % inv_len] == '1':
                    if c == '1':
                        current_char_bits += '0'
                    else:
                        current_char_bits += '1'

                else:
                    current_char_bits += c
                bit_to_decode += 1
            bit_to_decode %= inv_len
            #current_char_bits += current_pkt_bits
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
