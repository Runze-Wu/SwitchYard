#!/usr/bin/env python3

from switchyard.lib.userlib import *
import time


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
    s = TestScenario("lru tests")
    case = [(1, 4), (2, 1), (3, 1), (4, 1), (5, 1), (6, 7),(4,2), (4, 5)]

    for i in range(8):
        s.add_interface('eth' + str(i), '90:00:00:00:00:0' + str(i))
    except_table = [[], [1], [1, 2], [1, 3, 2], [1, 4, 3, 2], [1, 5, 4, 3, 2],
                    [6, 1, 5, 4, 3],[6,1,5,4,3], [5, 6, 1, 4, 3]]
    # 1 to 4
    mypkt = mk_pkt(
        str(1) + '0:00:00:00:00:00',
        str(4) + '0:00:00:00:00:00',
        str(1) + '.0.0.0',
        str(4) + '.0.0.0')
    s.expect(PacketInputEvent('eth' + str(1), mypkt, display=Ethernet),
             "Ethernet frame from mac {} to mac {}".format(1, 4))
    s.expect(
        PacketOutputEvent('eth0',
                          mypkt,
                          'eth2',
                          mypkt,
                          'eth3',
                          mypkt,
                          'eth4',
                          mypkt,
                          'eth5',
                          mypkt,
                          'eth6',
                          mypkt,
                          'eth7',
                          mypkt,
                          display=Ethernet),
        "forward table don't have mac4's port and flood out packet")
    # 2 to 1
    mypkt = mk_pkt(
        str(2) + '0:00:00:00:00:00',
        str(1) + '0:00:00:00:00:00',
        str(2) + '.0.0.0',
        str(1) + '.0.0.0')
    s.expect(PacketInputEvent('eth' + str(2), mypkt, display=Ethernet),
             "Ethernet frame from mac {} to mac {}".format(2, 1))
    s.expect(PacketOutputEvent('eth1', mypkt, display=Ethernet),
             "forward table should have mac1's port")
    # 3 to 1
    mypkt = mk_pkt(
        str(3) + '0:00:00:00:00:00',
        str(1) + '0:00:00:00:00:00',
        str(3) + '.0.0.0',
        str(1) + '.0.0.0')
    s.expect(PacketInputEvent('eth' + str(3), mypkt, display=Ethernet),
             "Ethernet frame from mac {} to mac {}".format(3, 1))
    s.expect(PacketOutputEvent('eth1', mypkt, display=Ethernet),
             "forward table should have mac1's port")
    # 4 to 1
    mypkt = mk_pkt(
        str(4) + '0:00:00:00:00:00',
        str(1) + '0:00:00:00:00:00',
        str(4) + '.0.0.0',
        str(1) + '.0.0.0')
    s.expect(PacketInputEvent('eth' + str(4), mypkt, display=Ethernet),
             "Ethernet frame from mac {} to mac {}".format(4, 1))
    s.expect(PacketOutputEvent('eth1', mypkt, display=Ethernet),
             "forward table should have mac1's port")
    # 5 to 1
    mypkt = mk_pkt(
        str(5) + '0:00:00:00:00:00',
        str(1) + '0:00:00:00:00:00',
        str(5) + '.0.0.0',
        str(1) + '.0.0.0')
    s.expect(PacketInputEvent('eth' + str(5), mypkt, display=Ethernet),
             "Ethernet frame from mac {} to mac {}".format(5, 1))
    s.expect(PacketOutputEvent('eth1', mypkt, display=Ethernet),
             "forward table should have mac1's port")
    # 6 to 7
    mypkt = mk_pkt(
        str(6) + '0:00:00:00:00:00',
        str(7) + '0:00:00:00:00:00',
        str(6) + '.0.0.0',
        str(7) + '.0.0.0')
    s.expect(PacketInputEvent('eth' + str(6), mypkt, display=Ethernet),
             "Ethernet frame from mac {} to mac {}".format(6, 7))
    s.expect(
        PacketOutputEvent('eth0',
                          mypkt,
                          'eth1',
                          mypkt,
                          'eth2',
                          mypkt,
                          'eth3',
                          mypkt,
                          'eth4',
                          mypkt,
                          'eth5',
                          mypkt,
                          'eth7',
                          mypkt,
                          display=Ethernet),
        "forward table don't have mac7's port and flood out packet")
     # 4 to 2
    mypkt = mk_pkt(
        str(4) + '0:00:00:00:00:00',
        str(2) + '0:00:00:00:00:00',
        str(4) + '.0.0.0',
        str(2) + '.0.0.0')
    s.expect(PacketInputEvent('eth' + str(4), mypkt, display=Ethernet),
             "Ethernet frame from mac {} to mac {}".format(4, 2))
    s.expect(
        PacketOutputEvent('eth0',
                          mypkt,
                          'eth1',
                          mypkt,
                          'eth2',
                          mypkt,
                          'eth3',
                          mypkt,
                          'eth5',
                          mypkt,
                          'eth6',
                          mypkt,
                          'eth7',
                          mypkt,
                          display=Ethernet),
        "forward table don't have mac2's port and flood out packet")
    # 4 to 5
    mypkt = mk_pkt(
        str(4) + '0:00:00:00:00:00',
        str(5) + '0:00:00:00:00:00',
        str(4) + '.0.0.0',
        str(5) + '.0.0.0')
    s.expect(PacketInputEvent('eth' + str(4), mypkt, display=Ethernet),
             "Ethernet frame from mac {} to mac {}".format(4, 5))
    s.expect(PacketOutputEvent('eth5', mypkt, display=Ethernet),
             "forward table should have mac5's port")

    return s


scenario = my_tests()
