#
# Laura Pickens
# packet_sniffer.py
# Original code found at www.binarytides.com/python-packet-sniffer-code-linux/, posted on Nov 29, 2011 by Silver Moon (m00n.silv3r@gmail.com)
# Modifications to original code are my own
# 

import socket, sys
from struct import *

# create an INET raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error, msg:
    print 'Socket could not be created. Error Code: ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(80)

    #packet string from tuple
    packet = packet[0]

    #take first 20 characters for the IP header
    ip_header = packet[0:20]

    #now unpack them
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    print '-----------------------PACKET-----------------------'
    print "IP Header Info              | TCP Header Info"
    ip_info = ['Version: ' + str(version),
               'IP Header Length: ' + str(ihl), 
               'TTL: ' + str(ttl),
               'Protocol: ' + str(protocol), 
               'Source Address: ' + str(s_addr), 
               'Dest Address: ' + str(d_addr)]

    tcp_header = packet[iph_length:iph_length+20]

    #now unpack them
    tcph = unpack('!HHLLBBHHH', tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4

    tcp_info = ['Source Port: ' + str(source_port),
                'Destination Port: ' + str(dest_port),
                'Sequence: ' + str(sequence), 
                'Acknowledgement: ' + str(acknowledgement), 
                'TCP Header Length: ' + str(tcph_length)]

    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    #get data from the packet
    data = packet[h_size:]

    #print ip and tcp header info
    for i in range(0,len(ip_info)):
        tcp_data = ""
        if i < len(tcp_info):
            tcp_data = tcp_info[i]
        print ip_info[i] + " "*(28-len(ip_info[i])) + "| " + tcp_data


    print 'Data: ' + data
    print '-----------------------PACKET-----------------------'
