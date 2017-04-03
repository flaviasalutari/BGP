#!/usr/bin/env python

__author__ = "bt3"

''' A class for the ICMP header'''

import ctypes



class ICMP(ctypes.Structure):

    _fields_ = [
    ('type',        ctypes.c_byte),
    ('code',        ctypes.c_byte),
    ('checksum',    ctypes.c_ushort),
    ('identifier',      ctypes.c_ushort),
    ('sequence_number',ctypes.c_short),
    ('o_timestamp',ctypes.c_uint),
    ('rx_timestamp',ctypes.c_uint),
    ('tx_timestamp',ctypes.c_uint)  
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass
