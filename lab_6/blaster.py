#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time
from struct import *


def create_seq_packet(seq_num, port_mac, length):
    eth_header = Ethernet(src=port_mac["blaster-eth0"],
                          dst=port_mac["middlebox-eth1"],
                          EtherType=EtherType.IP)
    ip_header = IPv4(src="192.168.100.1",
                     dst="192.168.200.1",
                     protocol=IPProtocol.UDP)
    udp_header = UDP(src=7777, dst=6666)
    rawpkt = RawPacketContents(
        pack('>I', seq_num) + pack('>H', length) + bytes(length))
    return eth_header + ip_header + udp_header + rawpkt


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    ip_mac = {
        "192.168.100.1": "10:00:00:00:00:01",
        "192.168.200.1": "20:00:00:00:00:01"
    }
    port_mac = {
        "blaster-eth0": "10:00:00:00:00:01",
        "blastee-eth0": "20:00:00:00:00:01",
        "middlebox-eth0": "40:00:00:00:00:01",
        "middlebox-eth1": "40:00:00:00:00:02"
    }
    begin_time = timer = time.time()  #record whole time and timer counter
    LHS = RHS = 1  #left right boarder
    blaster_params = open("blaster_params.txt", 'r')
    line = blaster_params.read().strip().split()
    if len(line) == 12:
        blastee_ip, num, length = line[1], line[3], line[5]
        sender_window, timeout, recv_timeout = line[7], line[9], line[11]
    blaster_params.close()

    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp, dev, pkt = net.recv_packet(timeout=recv_timeout)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
        else:
            log_debug("Didn't receive anything")
            '''
            Creating the headers for the packet
            '''
            pkt = Ethernet() + IPv4() + UDP()
            pkt[1].protocol = IPProtocol.UDP
            '''
            Do other things here and send packet
            '''

    net.shutdown()
