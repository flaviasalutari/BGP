#!/usr/bin/env python

import socket
import os
import struct
import ctypes
from ICMPHeader import ICMP
from IPHeader import IP 
import sys
from prova import *
def main():                
    output=open(sys.argv[1],'w')

    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    #sniffer.bind(( HOST, 0 ))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print "started"
    # continually read in packets and parse their information
    while True:
        # read in a packet and pass the first 20 bytes to initialize the IP structure
        #raw_buffer = sniffer.recvfrom(65565)[0]
        try:
            raw_buffer = sniffer.recv(58)
            #add only the black list
            (typeIcmp, code) = struct.unpack("!bb", raw_buffer[20:22])#self._at(packet, OFF_ICMP, 2, 'bb')        

            if typeIcmp == 3 and code >=9 and code <=13: #Type 3: Destination Unreachable (INVALID ANSWER)                   
                #self.destsUnreachable.append(sorceIp) 
                timecount +=1 
            if typeIcmp == 14:    
                #take first 20 characters for the ip header
                ip_header = IP(raw_buffer[0:20])
                icmp_header = ICMP(raw_buffer[20:40])
                """
                print 'IP -> Version:' + str(ip_header.version) + ', Header Length:' + str(ip_header.ihl) + \
                ', TTL:' + str(ip_header.ttl) + ', Protocol:' + str(ip_header.protocol) + ', Source:'\
                 + str(ip_header.src_address) + ', Destination:' + str(ip_header.dst_address)
                """
                #print ip_header.src_address,ip_header.dst_address, ip_header.ttl,ip_header.id
                #, icmp_header.o_timestamp, icmp_header.tx_timestamp, icmp_header.rx_timestamp
                #\t%s\t%s\t%s
                output.write("%s\t%s\t%s\t%s\t%s\t%s\n" %(ip_header.src_address, ip_header.dst_address ,ip_header.id, icmp_header.o_timestamp, icmp_header.rx_timestamp, icmp_header.tx_timestamp ))
                print ("%s\t%s\t%s\t%s\t%s\t%s\n" %(ip_header.src_address, ip_header.dst_address ,ip_header.id, icmp_header.o_timestamp, icmp_header.rx_timestamp, icmp_header.tx_timestamp ))
        except KeyboardInterrupt:
                output.write("test")
                print "Closing the file"
                output.close()
                sys.exit()

            

if __name__ == '__main__':
    main()
