#!/usr/bin/env python3
'''
Basic IPv4 router (static routing) in Python.
'''

from struct import pack
import sys
import os
import time
from switchyard.lib.userlib import *
from switchyard.lib.address import *


class PktCache:
    def __init__(self):
        self.cache_packet = dict()

    def AddPacket(self, src_mac, src_ip, dst_ip, packet, port, IsIcmp=False):
        if dst_ip not in self.cache_packet:
            self.cache_packet[dst_ip] = list()
            self.cache_packet[dst_ip].append(
                [time.time(), 1, src_ip, src_mac, port])
        self.cache_packet[dst_ip].append((packet, IsIcmp))
        return (create_ip_arp_request(src_mac, src_ip, dst_ip), port)

    def GetArpReply(self, get_ip):
        if get_ip in self.cache_packet:
            return self.cache_packet[get_ip]
        return list()

    def GetArpIcmp(self, packet):
        log_info("arp timelimit no  arp reply packet")
        index = packet.get_header_index(Ethernet)
        del packet[index]
        icmp = ICMP()
        icmp.icmptype = ICMPType.DestinationUnreachable
        icmp.icmpcode = ICMPCodeDestinationUnreachable.HostUnreachable
        icmp.icmpdata.data = packet.to_bytes()[:28]
        ip = IPv4(protocol=IPProtocol.ICMP, ttl=10, dst=packet[IPv4].src)
        ethr = Ethernet()
        # log_info(str(icmp))
        arp_error_pkt = ethr + ip + icmp
        return arp_error_pkt

    def GapArpQuery(self):
        now = time.time()
        cache_packet_list = list(self.cache_packet.items())
        cache_packet_list.sort(key=lambda x: x[1][0][0])
        arp_packets = list()
        icmp_packets = list()
        for item in cache_packet_list:
            if item[1][0][
                    1] <= 4 and now - item[1][0][0] - item[1][0][1] >= 0.0:
                port, src_mac, src_ip, nexthop = item[1][0][4], item[1][0][
                    3], item[1][0][2], item[0]
                arp_packets.append(
                    (create_ip_arp_request(src_mac, src_ip, nexthop), port))
                self.cache_packet[item[0]][0][1] += 1
            elif item[1][0][1] >= 5 or now - item[1][0][0] > 4.0:
                for num in range(1, len(item[1])):
                    icmp_packets.append(self.GetArpIcmp(item[1][num][0]))
                self.cache_packet.pop(item[0])
        return arp_packets, icmp_packets

    pass


class Router(object):
    def __init__(self, net):
        self.net = net
        self.arp_table = dict()
        self.mycache = PktCache()
        #subnet netmask nexthopip interface
        self.router_table = list()
        self.port_mac = {
            intf.name: intf.ethaddr
            for intf in self.net.interfaces()
        }
        self.port_ip = {
            intf.name: intf.ipaddr
            for intf in self.net.interfaces()
        }
        self.mac_ip = {
            intf.ethaddr: intf.ipaddr
            for intf in self.net.interfaces()
        }
        self.ip_mac = {
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
        # log_info("build from file: {}".format(self.router_table))
        myfile.close()
        for intf in self.net.interfaces():
            self.router_table.append(
                (str(intf.ipaddr), str(intf.netmask), '#', str(intf.name)))
        log_info("build result: {}".format(self.router_table))
        return

    def forward_packet(self, port, packet):
        if packet[Ethernet].ethertype == EtherType.ARP:
            if packet[Arp].operation == ArpOperation.Request:
                self.process_arp_request(port, packet)
            elif packet[Arp].operation == ArpOperation.Reply:
                self.process_arp_reply(port, packet)
        elif packet[Ethernet].ethertype == EtherType.IPv4:
            if packet[IPv4].dst in self.ip_mac:
                log_info("Packet intended for me")
                if packet[IPv4].protocol == IPProtocol.ICMP:
                    if packet[ICMP].icmptype == ICMPType.EchoRequest:
                        self.Icmp_reply(packet)
                else:
                    self.Icmp_reply(packet, False)
            else:
                self.process_IP_Packet(packet)
        else:
            log_info("other type packet")
        return

    def Icmp_reply(self, packet, legal=True):
        index = packet.get_header_index(Ethernet)
        del packet[index]
        icmp = ICMP()
        ip = IPv4(protocol=IPProtocol.ICMP, ttl=10, dst=packet[IPv4].src)
        if legal:
            log_info("ICMP request for the router")
            icmp.icmptype = ICMPType.EchoReply
            icmp.icmpdata.sequence = packet[ICMP].icmpdata.sequence
            icmp.icmpdata.identifier = packet[ICMP].icmpdata.identifier
            icmp.icmpdata.data = packet[ICMP].icmpdata.data
            ip.src = packet[IPv4].dst
        else:
            log_info("the destination is router but isn't ICMP request")
            icmp.icmptype = ICMPType.DestinationUnreachable
            icmp.icmpcode = ICMPCodeDestinationUnreachable.PortUnreachable
            icmp.icmpdata.data = packet.to_bytes()[:28]
        log_info("the data is {}".format(icmp.icmpdata.data))
        # log_info(str(icmp))
        reply_pkt = Ethernet() + ip + icmp
        self.process_IP_Packet(reply_pkt, True, legal == False)
        pass

    def match_subnet(self, dst_ip):
        maxlen, tar_route = 0, None
        for item in self.router_table:
            subnet = IPv4Network(item[0] + '/' + item[1], False)
            if dst_ip in subnet:
                if maxlen < subnet.prefixlen:
                    tar_route, maxlen = item, subnet.prefixlen
        return tar_route

    def IP_forward(self, packet, port, dst_mac, IsErrorIcmp=False):
        packet[Ethernet].dst, packet[IPv4].ttl = dst_mac, packet[IPv4].ttl - 1

        if IsErrorIcmp:
            packet[IPv4].src = self.port_ip[port]
        log_info("{} send IP packet {}".format(port, packet))
        self.net.send_packet(port, packet)

    def process_IP_Packet(self, packet, IsIcmp=False, IsErrorIcmp=False):
        log_info("catch an IP packet {}".format(packet))
        if packet[IPv4].ttl <= 1:
            log_info("ttl is limited")
            index = packet.get_header_index(Ethernet)
            del packet[index]
            icmp = ICMP()
            icmp.icmptype = ICMPType.TimeExceeded
            icmp.icmpcode = ICMPCodeTimeExceeded.TTLExpired
            icmp.icmpdata.data = packet.to_bytes()[:28]
            ip = IPv4(protocol=IPProtocol.ICMP, ttl=10, dst=packet[IPv4].src)
            ttl_pkt = Ethernet() + ip + icmp
            self.process_IP_Packet(ttl_pkt, True, True)
            return
        dst_ip = packet[IPv4].dst
        tar_route = self.match_subnet(dst_ip)
        if tar_route is None:
            log_info("can't match to any subnet")
            index = packet.get_header_index(Ethernet)
            del packet[index]
            icmp = ICMP()
            icmp.icmptype = ICMPType.DestinationUnreachable
            icmp.icmpcode = ICMPCodeDestinationUnreachable.NetworkUnreachable,
            icmp.icmpdata.data = packet.to_bytes()[:28]
            ip = IPv4(protocol=IPProtocol.ICMP, ttl=10, dst=packet[IPv4].src)
            ethr = Ethernet()
            time_pkt = ethr + ip + icmp
            self.process_IP_Packet(time_pkt, True, True)
        else:
            log_info("the forwarding entry is {}".format(tar_route))
            src_mac = self.port_mac[tar_route[3]]
            packet[Ethernet].src = src_mac
            nexthop = tar_route[2]
            if tar_route[2] == '#':
                nexthop = dst_ip
            nexthop = IPv4Address(nexthop)
            if nexthop in self.arp_table:
                self.IP_forward(packet, tar_route[3],
                                self.arp_table[nexthop][0], IsErrorIcmp)
            else:
                has_same_arp = False
                if tar_route[2] != '#' and self.match_subnet(nexthop) is None:
                    return
                if nexthop in self.mycache.cache_packet:
                    has_same_arp = True
                request_pkt = self.mycache.AddPacket(src_mac,
                                                     self.mac_ip[src_mac],
                                                     nexthop, packet,
                                                     tar_route[3], IsErrorIcmp)
                if has_same_arp:
                    log_info("already has the same arp request")
                    return
                log_info("{} send Arp request: {}".format(
                    request_pkt[1], request_pkt[0]))
                self.net.send_packet(request_pkt[1], request_pkt[0])
        return

    def arp_repeat(self):
        arp_packets, icmp_packets = self.mycache.GapArpQuery()
        for pkt in arp_packets:
            self.net.send_packet(pkt[1], pkt[0])
        for pkt in icmp_packets:
            self.process_IP_Packet(pkt, True, True)
            pass

    def add_arp_table(self, src_ip, src_mac):
        self.arp_table[src_ip] = (src_mac, time.time())
        log_info("update {}".format(self.arp_table))
        if src_ip in self.mycache.cache_packet:
            cache_pkts = self.mycache.GetArpReply(src_ip)
            port = cache_pkts[0][4]
            for i in range(1, len(cache_pkts)):
                self.IP_forward(cache_pkts[i][0], port, src_mac,
                                cache_pkts[i][1])
            self.mycache.cache_packet.pop(src_ip)

    def process_arp_reply(self, port, packet):
        log_info('{} Got a ARP Reply {}'.format(port, packet))
        arp = packet[Arp]
        src_mac, src_ip = arp.senderhwaddr, arp.senderprotoaddr
        self.add_arp_table(src_ip, src_mac)
        return

    def process_arp_request(self, port, packet):
        log_info('{} Got a ARP Reply {}'.format(port, packet))
        arp = packet[Arp]
        src_mac, src_ip, dst_ip = arp.senderhwaddr, arp.senderprotoaddr, arp.targetprotoaddr
        self.add_arp_table(src_ip, src_mac)
        if dst_ip in self.ip_mac:
            arppacket = create_ip_arp_reply(self.ip_mac[dst_ip], src_mac,
                                            dst_ip, src_ip)
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
