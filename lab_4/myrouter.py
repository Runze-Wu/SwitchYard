#!/usr/bin/env python3
'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *
from switchyard.lib.address import *

# class PktCache:
#     def __init__(self):
#         self.cache_packet = dict()

#     pass


class Router(object):
    def __init__(self, net):
        self.cache_packet = dict()
        self.net = net
        self.arp_table = dict()
        #subnet netmask nexthopip interface
        self.router_table = list()
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

    def built_router_table(self, filename):
        myfile = open(filename, 'r')
        for line in myfile.readlines():
            line = line.strip().split()
            if len(line) == 4:
                self.router_table.append((line[0], line[1], line[2], line[3]))
        print("build from file: {}".format(self.router_table))
        myfile.close()
        for intf in self.net.interfaces():
            self.router_table.append(
                (str(intf.ipaddr), str(intf.netmask), '#', str(intf.name)))
        print("build from interface: {}".format(self.router_table))
        return

    def forward_packet(self, port, packet):
        now_time = time.time()
        if packet[Ethernet].ethertype == EtherType.ARP:
            if packet[Arp].operation == ArpOperation.Request:
                self.process_arp_request(port, packet)
            elif packet[Arp].operation == ArpOperation.Reply:
                self.process_arp_reply(port, packet)
        elif packet[Ethernet].ethertype == EtherType.IPv4:
            if packet[IPv4].dst in self.mydic:
                log_info("Packet intended for me")
            else:
                self.process_IP_Packet(packet)
        else:
            log_info("other type packet")
        return

    def match_subnet(self, dst_ip):
        maxlen = 0
        tar_route = None
        for item in self.router_table:
            subnet = IPv4Network(item[0] + '/' + item[1], False)
            if dst_ip in subnet:
                if maxlen < subnet.prefixlen:
                    tar_route, maxlen = item, subnet.prefixlen
        return tar_route

    def IP_forward(self, packet, port, dst_mac):
        packet[Ethernet].dst = dst_mac
        packet[IPv4].ttl = packet[IPv4].ttl - 1
        packet[IPv4].checksum
        log_info(packet)
        self.net.send_packet(port, packet)

    def process_IP_Packet(self, packet):
        print("catch an IP packet {}".format(packet))
        ip_pkt = packet[IPv4]
        src_mac, src_ip, dst_ip, ttl, pro = packet[
            Ethernet].src, ip_pkt.src, ip_pkt.dst, ip_pkt.ttl, ip_pkt.protocol
        log_info("IPv4 pkt src: {} dst: {}  ttl: {} protocol: {}".format(
            src_ip, dst_ip, ttl, pro))
        tar_route = self.match_subnet(dst_ip)
        if tar_route is None:
            log_info("can't match to any subnet")
        else:
            for intf in self.net.interfaces():
                if tar_route[3] == intf.name:
                    src_mac = intf.ethaddr
                    break
            packet[Ethernet].src = src_mac
            nexthop = tar_route[2]
            if tar_route[2] == '#':
                nexthop = dst_ip
            nexthop = IPv4Address(nexthop)
            if nexthop in self.arp_table:
                self.IP_forward(packet, tar_route[3],
                                self.arp_table[nexthop][0])
            else:
                if nexthop not in self.cache_packet:
                    self.cache_packet[nexthop] = list()
                    self.cache_packet[nexthop].append([time.time(), 0])
                self.cache_packet[nexthop].append((packet, tar_route[3]))
                self.arp_repeat()
        return

    def arp_query(self, src_mac, src_ip, dst_ip, port):
        print(src_mac, src_ip, dst_ip, port)
        print(type(src_mac), type(src_ip), type(dst_ip))
        request_pkt = create_ip_arp_request(src_mac, src_ip, dst_ip)
        print("Arp request: " + str(request_pkt) + str(port))
        self.net.send_packet(port, request_pkt)

    def arp_repeat(self):
        now = time.time()
        cache_packet_list = list(self.cache_packet.items())
        cache_packet_list.sort(key=lambda x: x[1][0][0])
        print(cache_packet_list)
        for item in cache_packet_list:
            if  item[1][0][1]<=4 and now - item[1][0][0] - item[1][0][1] >= 0.0:
                # if item[1][0][1] == 0:
                tar_route = self.match_subnet(item[0])
                nexthop = tar_route[2]
                if tar_route[2] == '#':
                    nexthop = item[0]
                src_mac = EthAddr()
                for intf in self.net.interfaces():
                    if tar_route[3] == intf.name:
                        src_mac = intf.ethaddr
                        break
                nexthop = IPv4Address(nexthop)
                self.arp_query(src_mac, IPv4Address(tar_route[0]), nexthop,
                               tar_route[3])
                self.cache_packet[item[0]][0][1] += 1
            elif item[1][0][1] >= 5 or now - item[1][0][0] >= 5.0:
                # elif item[1][0][1] >= 4:
                self.cache_packet.pop(item[0])
            

    def process_arp_reply(self, port, packet):
        log_info('Got a ARP Reply')
        arp = packet[Arp]
        src_mac, src_ip, dst_mac, dst_ip = arp.senderhwaddr, arp.senderprotoaddr, arp.targethwaddr, arp.targetprotoaddr
        log_info("{} {} {} {} {}".format(src_mac, src_ip, dst_mac, dst_ip,
                                         arp.operation))
        self.arp_table[src_ip] = (src_mac, time.time())
        if src_ip in self.cache_packet:
            for i in range(1, len(self.cache_packet[src_ip])):
                print(self.cache_packet[src_ip][i])
                self.IP_forward(self.cache_packet[src_ip][i][0],
                                self.cache_packet[src_ip][i][1], src_mac)
            self.cache_packet.pop(src_ip)
        log_info("update {}".format(self.arp_table))
        return

    def process_arp_request(self, port, packet):
        log_info('Got a ARP Request')
        arp = packet[Arp]
        src_mac, src_ip, dst_mac, dst_ip = arp.senderhwaddr, arp.senderprotoaddr, arp.targethwaddr, arp.targetprotoaddr
        log_info("{} {} {} {} {}".format(src_mac, src_ip, dst_mac, dst_ip,
                                         arp.operation))
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
                self.arp_repeat()
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                self.forward_packet(dev, pkt)


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
