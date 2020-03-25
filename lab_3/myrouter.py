#!/usr/bin/env python3
'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        my_interfaces = self.net.interfaces()
        mydic = {intf.ipaddr: intf.ethaddr for intf in my_interfaces}
        arp_table,max_time=dict(),10.0
        while True:
            gotpkt = True
            try:
                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            now_time=time.time()
            for key,value in list(arp_table.items()):
                if now_time-value[1]>=max_time:
                    log_info("del {}:{}".format(key,value))
                    arp_table.pop(key)
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
            if pkt[Ethernet].ethertype == EtherType.ARP:
                log_info('Got a ARP packet')
                arp = pkt[Arp]
                src_mac, src_ip, dst_mac, dst_ip = arp.senderhwaddr, arp.senderprotoaddr, arp.targethwaddr, arp.targetprotoaddr
                log_info("{} {} {} {} {}".format(src_mac, src_ip, dst_mac,dst_ip,arp.operation))
                if arp.operation == ArpOperation.Request and dst_ip in mydic:
                    arp_table[src_ip]=(src_mac,now_time)
                    ether = Ethernet(src=mydic[dst_ip],
                                     dst=src_mac,
                                     ethertype=EtherType.ARP)

                    arp = Arp(operation=ArpOperation.Reply,
                              senderhwaddr=mydic[dst_ip],
                              senderprotoaddr=dst_ip,
                              targethwaddr=src_mac,
                              targetprotoaddr=src_ip)
                    arppacket = ether + arp
                    log_info(arppacket)
                    self.net.send_packet(dev, arppacket)


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
