# Covert Storage Channel that exploits Protocol Field Manipulation using Source IP Address field in ARP

A simple layer 2 covert channel implementation which uses ARP. 

## Introduction

This is implementation of covert channel is quite simple it uses source IP field in ARP to transmit the message. In doing so it gives the user flexibility. The sender and receiver handshakes before the transmission occurs. The hand shake is performed on the followıng before runtime:

- The bits that will be actually used in data transmission
- The bits that will be manipulated for encoding the message
- The destination IP address in ARP protocol

These are needed to be known beforehand because of the following reasons, The receiver should filter out the packets that are coming from only the sender. Also the covert channel will not use the whole source IP field for transmission only a selected portion of the 32 bits in source IP field be actually be meaningfull, i.e part of the message, and these bits will be inverted using a given binary array. For instance If the mask given for the meaningfull bits are "0x0000FF00" then only the least significant second byte will be overwritten in the sender with the actual message. Also before the message bits are embedded to the IP, a very simple encoding is used. The sender and receiver takes a binary string and if the bit in the position the message bit is 1 in this encoding string then that bit is inverted if not it is left as it is. When the binary string used for encoding is finished it is repeated as many times as it is required.

The aforementioned parameter must be defined by the user in the config.json file. A sample one is provided in the code directory. Also sender and reciever **must** acquire the same parameters. And the parameter must be in the following format inside the json file

- mask : 32 bit hexadecimal number in a string type
- enc_mask : A binary string consisting of characters of only '1' and '0'. It's lenght is arbitrary left to user
- destination IP in the dotted integer format in a string e.g "192.168.1.5"

## Capacity of the covered channel 
Actually this implementation's capacity is quite varying depending on the number of 1's in the mask of the message. Since the this is a covert channel it is not advisable to use all of the bits in the source IP for data transmission. Hence we measured the capacity using only 8 bits for message transmission. Meaning only 8 bits are encoded and transmitted with each packet. The measured capacity was around 166 bits per second. Depending on the run capacity changed from 160 to 183 bits per second
