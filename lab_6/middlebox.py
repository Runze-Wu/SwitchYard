#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
from random import randint
import time


def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
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
            timestamp, dev, pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            drop_rate = float(0)
            middlbox_params = open("middlebox_params.txt", 'r')
            line = middlbox_params.read().strip().split()
            if len(line) == 2:
                drop_rate = float(line[1])
            middlbox_params.close()
            if randint(0, 100) < drop_rate * 100:  #丢弃
                pass
            else:  #进行发送
                print(2)
                pkt[Ethernet].src = port_mac[dev]
                pkt[Ethernet].dst = ip_mac[str(pkt[IPv4].dst)]
                net.send_packet("middlebox-eth1", pkt)
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            print(pkt)
            print(1)
            pkt[Ethernet].src = port_mac[dev]
            print(pkt[Ethernet].dst)
            print(ip_mac[str(pkt[IPv4].dst)])
            pkt[Ethernet].dst = ip_mac[str(pkt[IPv4].dst)]
            print(1)
            print(pkt)
            net.send_packet("middlebox-eth0", pkt)
            print(1)
        else:
            log_debug("Oops :))")

    net.shutdown()
