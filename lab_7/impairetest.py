#!/usr/bin/env python3

from random import randint
from copy import deepcopy
import struct
import time

from switchyard.lib.userlib import *

firewall_rules = '''
# rule 1
permit tcp src 192.168.0.0/24 srcport any dst any dstport 8000 impair
# rule2
permit icmp src any dst any impair
'''

def rand16(start=0):
    return randint(start,2**16-1)

def rand32(start=0):
    return randint(start, 2**32-1)

def rand8(start=0):
    return randint(start, 2**8-1)

def mketh(xtype = EtherType.IP):
    e = Ethernet()
    e.ethertype = xtype
    e.src = struct.pack('xxI',rand32())
    e.dst = struct.pack('xxI',rand32())
    return e

def swap(pkt):
    pkt = deepcopy(pkt)
    e = pkt.get_header(Ethernet)
    e.src,e.dst = e.dst,e.src
    ip = pkt.get_header(IPv4)
    ip.src,ip.dst = ip.dst, ip.src
    ip.ttl = 255-ip.ttl
    ip.ipid = 0
    tport = None
    if pkt.has_header(TCP):
        tport = pkt.get_header(TCP)
        tport.seq, tport.ack = tport.ack, tport.seq
        tport.ACK = 1
    elif pkt.has_header(UDP):
        tport = pkt.get_header(UDP)
    if tport is not None:
        tport.src,tport.dst = tport.dst, tport.src
    return pkt

def firewall_tests():
    s = TestScenario("Firewall tests")
    s.add_file('firewall_rules.txt', firewall_rules)

    # two ethernet ports; no IP addresses assigned to
    # them.  eth0 is internal network-facing, and eth1
    # is external network-facing.
    s.add_interface('eth0', '00:00:00:00:0b:01')
    s.add_interface('eth1', '00:00:00:00:0b:02')

    # first set of tests: check that packets that should be allowed through
    # are allowed through
    t = TCP() 
    t.SYN = 1
    t.src = rand16(10000)
    t.dst = 8000
    t.seq = rand32()
    t.ack = rand32()
    t.window = rand16(8192)
    ip = IPv4()
    ip.src = '192.168.0.13'
    ip.dst = rand32()
    ip.ttl = rand8(12)     
    ip.protocol = IPProtocol.TCP
    pkt = mketh() + ip + t
    s.expect(PacketInputEvent('eth0',pkt), 
        'Packet arriving on eth0 should be impaired since it matches rule 1.')
    impaired_pkt=pkt+b'impaired'
    s.expect(PacketOutputEvent('eth1',impaired_pkt),
        'Packet forwarded out eth1; impaired since it matches rule 1.')
    
    
    ip.src = rand32()
    ip.dst = rand32()
    ip.protocol = IPProtocol.ICMP
    icmp_pkt = ICMP()
    icmp_pkt.icmpdata.data = int(1).to_bytes(length=75, byteorder='big')
    pkt = mketh() + ip + icmp_pkt
    payload = '''lambda pkt: pkt.get_header(ICMP).icmpdata.data[:8]==b'impaired' '''
    s.expect(PacketInputEvent('eth0', pkt),
        'Packet arriving on eth0 should be impaired since it matches rule 2.')
    s.expect(PacketOutputEvent('eth1', pkt,exact=False,predicate=payload),
        'Packet forwarded out eth1; impaired since it matches rule 2.')
    return s

scenario = firewall_tests()
