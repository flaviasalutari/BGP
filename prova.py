

import time
import socket
import struct
import select
import random

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 13 # Seems to be the same on Solaris.

ICMP_CODE = socket.getprotobyname('icmp')
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
    }

__all__ = ['create_packet', 'do_one', 'verbose_ping']


def checksum(source_string):
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1])*256+ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff # Necessary?
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet(id):
	"""Create a new echo request packet based on the given "id"."""
	# Header is type (8), code (8), checksum (16), id (16), sequence (16)
	from datetime import datetime, time
	utcnow = datetime.utcnow()
	midnight_utc = datetime.combine(utcnow.date(), time(0))
	delta = utcnow - midnight_utc
	header = struct.pack('bbHHhIII', ICMP_ECHO_REQUEST, 0, 0, id, 1, int(delta.total_seconds()) * 1000, int(delta.total_seconds()) * 1000,int(delta.total_seconds()) * 1000) #current timestamp
	data = 180 * 'Q'
	# Calculate the checksum on the data and the dummy header.
	my_checksum = checksum(header + data)
	# Now that we have the right checksum, we put that in. It's just easier
	# to make up a new header than to stuff it into the dummy.
	header = struct.pack('bbHHhIII', ICMP_ECHO_REQUEST, 0,
	                     socket.htons(my_checksum), id, 1, int(delta.total_seconds()) * 1000, int(delta.total_seconds()) * 1000,int(delta.total_seconds()) * 1000)
	return header + data

def do_one(dest_addr, timeout=1):
    """
    Sends one ping to the given "dest_addr" which can be an ip or hostname.
    "timeout" can be any integer or float except negatives and zero.
    Returns either the delay (in seconds) or None on timeout and an invalid
    address, respectively.
    """
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    except socket.error as e:
        if e.errno in ERROR_DESCR:
            # Operation not permitted
            raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
        raise # raise the original error
    try:
        host = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        return
    # Maximum for an unsigned short int c object counts to 65535 so
    # we have to sure that our packet id is not greater than that.
    packet_id = int((id(timeout) * random.random()) % 65535)
    packet = create_packet(packet_id)
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = my_socket.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]
    delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return delay


def receive_ping(my_socket, packet_id, time_sent, timeout):
    # Receive the ping from the socket.
	time_left = timeout
	while True:
		started_select = time.time()
		ready = select.select([my_socket], [], [], time_left)
		how_long_in_select = time.time() - started_select
		if ready[0] == []: # Timeout
			return
		time_received = time.time()
		rec_packet, addr = my_socket.recvfrom(1024)

		icmp_header = rec_packet[20:40]

		type_, code, checksum, p_id, sequence, originate, received, transmit = struct.unpack('bbHHhIII', icmp_header)
		print "type " + str(type_)
		print "code " + str(code)
		print "checksum " + str(checksum)
		print "p_id " + str(p_id)
		print "sequence " + str(sequence)
		print "Originate " + str(originate)
		print "Received " + str(received)
		print "transmit " + str(transmit)
        return

def verbose_ping(dest_addr, timeout=2, count=10):
    """
    Sends one ping to the given "dest_addr" which can be an ip or hostname.
    "timeout" can be any integer or float except negatives and zero.
    "count" specifies how many pings will be sent.
    Displays the result on the screen.
 
    """
    for i in range(count):
        print('ping {}...'.format(dest_addr))
        delay = do_one(dest_addr, timeout)
        if delay == None:
            print('failed. (Timeout within {} seconds.)'.format(timeout))
        else:
            delay = round(delay * 1000.0, 4)
            print('get ping in {} milliseconds.'.format(delay))
    print('')





if __name__ == '__main__':
    # Testing

    verbose_ping('64.137.245.229')
