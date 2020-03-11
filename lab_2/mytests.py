#!/usr/bin/env python3

from switchyard.lib.userlib import *

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def my_tests():
    s = TestScenario("hub tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')

    # test case 1: add "30:00:00:00:00:02 : eth1" 
    testpkt = mk_pkt("30:00:00:00:00:02", "ff:ff:ff:ff:ff:ff", "3.3.3.3", "255.255.255.255")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet), "The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2")

    # test case 2: match "30:00:00:00:00:02 : eth1"   add "20:00:00:00:00:01 : eth0" 
    reqpkt = mk_pkt("20:00:00:00:00:01", "30:00:00:00:00:02", '2.2.2.2','3.3.3.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "An Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt,  display=Ethernet), "Ethernet frame destined for 30:00:00:00:00:02 should be send out on eth1") 

    # test case 3: match "20:00:00:00:00:01 : eth0"   add "40:00:00:00:00:02 eth2"
    resppkt = mk_pkt("40:00:00:00:00:02", "20:00:00:00:00:01", '4.4.4.4', '2.2.2.2')
    s.expect(PacketInputEvent("eth2", resppkt, display=Ethernet), "An Ethernet frame from 30:00:00:00:00:02 to 20:00:00:00:00:01 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, display=Ethernet), "Ethernet frame destined to 20:00:00:00:00:01 should be send out on eth0")
    return s

scenario = my_tests()
