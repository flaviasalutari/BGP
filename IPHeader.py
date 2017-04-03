#!/usr/bin/env python

#modified with this: http://stackoverflow.com/questions/29306747/python-sniffing-from-black-hat-python-book

''' A class for the IP header'''
#TODO add rtt read from the sender

import os
import struct
import socket
import ctypes
        

class IP(ctypes.Structure):
    _fields_ = [
        ('ihl',         ctypes.c_ubyte, 4),
        ('version',     ctypes.c_ubyte, 4),
        ('tos',         ctypes.c_ubyte),
        ('len',         ctypes.c_ushort),
        ('id',          ctypes.c_ushort.__ctype_be__), #big endian
        ('offset',      ctypes.c_ushort),
        ('ttl',         ctypes.c_ubyte),
        ('protocol_num',ctypes.c_ubyte),
        ('sum',         ctypes.c_ushort),
        ('src',         ctypes.c_uint32),
        ('dst',         ctypes.c_uint32)
    ]


    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1:'ICMP', 6:'TCP', 17:'UDP'}

        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))
        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
