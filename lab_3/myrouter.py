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
        self.arp_table = dict()
        self.mydic = {
            intf.ipaddr: intf.ethaddr
            for intf in self.net.interfaces()
        }
        self.max_arp_time = 10.0
        # other initialization stuff here
    def refresh_arp_table(self, time):
        for key, value in list(self.arp_table.items()):
            if time - value[1] >= self.max_arp_time:
                log_info("del {}:{}".format(key, value))
                arp_table.pop(key)

    def forward_packet(self, port, packet):        
        now_time = time.time()
        self.refresh_arp_table(now_time)
        if packet[Ethernet].ethertype == EtherType.ARP:
            if packet[Arp].operation == ArpOperation.Request:
                self.arp_request(port, packet)
            elif packet[Arp].operation == ArpOperation.Reply:
                self.arp_reply(port, packet)
        elif packet[Ethernet].ethertype == EtherType.IPv4:
            return

    def arp_reply(self, port, packet):
        return

    def arp_request(self, port, packet):
        log_info('Got a ARP Request')
        arp = packet[Arp]
        src_mac, src_ip, dst_mac, dst_ip = arp.senderhwaddr, arp.senderprotoaddr, arp.targethwaddr, arp.targetprotoaddr
        log_info("{} {} {} {} {}".format(src_mac, src_ip, dst_mac, dst_ip,
                                         arp.operation))
        if dst_ip in self.mydic:
            self.arp_table[src_ip] = (src_mac, time.time())
            ether = Ethernet(src=self.mydic[dst_ip],
                             dst=src_mac,
                             ethertype=EtherType.ARP)
            arp = Arp(operation=ArpOperation.Reply,
                      senderhwaddr=self.mydic[dst_ip],
                      senderprotoaddr=dst_ip,
                      targethwaddr=src_mac,
                      targetprotoaddr=src_ip)
            arppacket = ether + arp
            log_info(arppacket)
            self.net.send_packet(port, arppacket)

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)
                self.forward_packet(dev,pkt)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            if gotpkt:
               log_debug("Got a packet: {}".format(str(pkt)))


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
