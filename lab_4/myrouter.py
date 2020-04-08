#!/usr/bin/env python3
'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *
from switchyard.lib.address import *
class classname(object):
    pass

class Router(object):
    def __init__(self, net):
        self.net = net
        self.arp_table = dict()
        #subnet netmask nexthopip interface
        self.router_table=list()
        self.mydic = {
            intf.ipaddr: intf.ethaddr
            for intf in self.net.interfaces()
        }
        self.max_arp_time = 10.0
        self.built_router_table("forwarding_table.txt")
        
    # other initialization stuff here
    def refresh_arp_table(self, time):
        for key, value in list(self.arp_table.items()):
            if time - value[1] >= self.max_arp_time:
                log_info("del {}".format(self.arp_table[key]))
                self.arp_table.pop(key)

    def built_router_table(self,filename):
        myfile=open(filename,'r');
        for line in myfile.readlines():
            line=line.split()
            self.router_table.append((line[0],line[1],line[2],line[3]))
        print("build from file: {}".format(self.router_table))
        myfile.close()
        for intf in self.net.interfaces():
            self.router_table.append((str(intf.ipaddr),str(intf.netmask),'#',str(intf.name)))
        print("build from interface: {}".format(self.router_table))
        return
    
    def forward_packet(self, port, packet):
        now_time = time.time()
        #self.refresh_arp_table(now_time)
        if packet[Ethernet].ethertype == EtherType.ARP:
            if packet[Arp].operation == ArpOperation.Request:
                self.process_arp_request(port, packet)
            elif packet[Arp].operation == ArpOperation.Reply:
                self.process_arp_reply(port, packet)
        elif packet[Arp].targetprotoaddr in self.mydic:
            log_debug("Packet intended for me")
            return
        elif packet[Ethernet].ethertype == EtherType.IPv4:
            self.process_IP_Packet(packet)
            return
        return

    def match_subnet(self,dst_ip):
        for item in (self.router_table):
            subnet=IPv4Network(str(item[0]+'/'+item[1]))
            if dst_ip in subnet:
                return item
        return None

    def process_IP_Packet(self,packet):
        return

    def arp_query(self,packet):
        return
    def process_arp_reply(self, port, packet):
        log_info('Got a ARP Reply')
        arp = packet[Arp]
        src_mac, src_ip, dst_mac, dst_ip = arp.senderhwaddr, arp.senderprotoaddr, arp.targethwaddr, arp.targetprotoaddr
        log_info("{} {} {} {} {}".format(src_mac, src_ip, dst_mac, dst_ip,arp.operation))
        self.arp_table[src_ip] = (src_mac, time.time())
        log_info("update {}".format(self.arp_table))
        return

    def process_arp_request(self, port, packet):
        log_info('Got a ARP Request')
        arp = packet[Arp]
        src_mac, src_ip, dst_mac, dst_ip = arp.senderhwaddr, arp.senderprotoaddr, arp.targethwaddr, arp.targetprotoaddr
        log_info("{} {} {} {} {}".format(src_mac, src_ip, dst_mac, dst_ip,arp.operation))
        self.arp_table[src_ip] = (src_mac, time.time())
        log_info("update {}".format(self.arp_table))
        if dst_ip in self.mydic:
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
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                self.forward_packet(dev,pkt)


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
