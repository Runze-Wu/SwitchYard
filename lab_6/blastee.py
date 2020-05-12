#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    ip_mac = {
        "192.168.100.1": "10:00:00:00:00:01",
        "192.168.200.1": "20:00:00:00:00:01"
    }
    port_mac = {
        "blaster-eth0":"10:00:00:00:00:01",
        "blastee-eth0":"20:00:00:00:00:01",
        "middlebox-eth0": "40:00:00:00:00:01",
        "middlebox-eth1": "40:00:00:00:00:02"
    }
    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
            if pkt[IPv4].dst!="192.168.200.1":
                log_info("the dst ipaddr isn't blastee")
                return
            blastee_params= open("blastee_params.txt", 'r')
            line =blastee_params.read().strip().split()
            if len(line) == 4:
                blaster_ip,num = line[1],line[3]
            blastee_params.close()
            eth_header=Ethernet(src=port_mac["blaster-eth0"],
                                dst=port_mac["middlebox-eth0"],
                                EtherType=EtherType.IP)
            ip_header=IPv4(src="192.168.200.1",
                           dst=blaster_ip)
            udp_header=UDP(src=7777,dst=6666)
            seq_num=RawPacketContents(pkt[RawPacketContents].to_bytes()[:32])
            add_payload=RawPacketContents(pkt[RawPacketContents].to_bytes()[48:56])
            ack_packet=eth_header+ip_header+udp_header+seq_num+add_payload
            net.send_packet("blaster-eth0", ack_packet)
    net.shutdown()
