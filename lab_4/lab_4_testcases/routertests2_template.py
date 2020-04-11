#!/usr/bin/env python

from switchyard.lib.userlib import *


def mk_arpreq(hwsrc, ipsrc, ipdst):
    return create_ip_arp_request(hwsrc, ipsrc, ipdst)


def mk_arpresp(arpreq, hwsrc, arphwsrc=None, arphwdst=None):
    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreq[1].senderhwaddr
    srcip = arpreq[1].targetprotoaddr
    targetip = arpreq[1].senderprotoaddr
    return create_ip_arp_reply(hwsrc, arphwdst, srcip, targetip)


def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64):
    ether = Ethernet()
    ether.src = hwsrc
    ether.dst = hwdst
    ippkt = IPv4()
    ippkt.src = ipsrc
    ippkt.dst = ipdst
    ippkt.ttl = ttl
    ippkt.ipid = 0
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = b'stuff!'

    return ether + ippkt + icmppkt


def write_table():
    table = '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
'''
    outfile = open('forwarding_table.txt', 'w')
    outfile.write(table)
    outfile.close()


def router_stage2():
    s = TestScenario("Router stage 2 additional test 1")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1',
                    '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1',
                    '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1',
                    '255.255.255.252')

    # case0 ping ip is one of the interface
    req_ping = mk_ping("00:00:00:00:00:00", 'ff:ff:ff:ff:ff:ff', '1.1.1.1',
                       '172.16.42.1')
    s.expect(
        PacketInputEvent('router-eth0', req_ping, display=IPv4),
        "send A ping request to 172.16.42.1(router-eth2) arrive on router-eth0"
    )
    s.expect(PacketInputTimeoutEvent(1.5),
             "the dst is one of the interface, so router just drop it")

    # case1 ping for ip:10.10.1.254 and src isn't in any subnet
    req_ping = mk_ping("00:00:00:00:00:00", 'ff:ff:ff:ff:ff:ff', '2.2.2.2',
                       '10.10.1.254')
    s.expect(PacketInputEvent('router-eth0', req_ping, display=IPv4),
             "send A ping request to 10.10.1.254 arrive on router-eth0")
    otroarp = mk_arpreq("10:00:00:00:00:02", "10.10.0.1", "10.10.1.254")
    s.expect(PacketOutputEvent('router-eth1', otroarp, display=Arp),
             "send Arp request for 10.10.1.254 leave out on router-eth1")
    otroarpresponse = mk_arpresp(otroarp, "11:00:00:00:00:00")
    s.expect(
        PacketInputEvent("router-eth1", otroarpresponse, display=Arp),
        "Router receive an ARP response for 10.10.1.254 on router-eth1 and prepare send the ping request to 10.10.1.254"
    )
    req_ping = mk_ping('10:00:00:00:00:02',
                       '11:00:00:00:00:00',
                       '2.2.2.2',
                       '10.10.1.254',
                       reply=False,
                       ttl=63)
    s.expect(
        PacketOutputEvent('router-eth1', req_ping, display=IPv4),
        "forward 2.2.2.2 to 10.10.1.254 ping request leave out on router-eth1")
    rep_ping = mk_ping("11:00:00:00:00:00", "10:00:00:00:00:02", "10.10.1.254",
                       '2.2.2.2', True)
    s.expect(PacketInputEvent('router-eth1', rep_ping, display=IPv4),
             "10.10.1.254 send ping reply to 2.2.2.2 arrive on router-eth1")
    s.expect(PacketInputTimeoutEvent(1),
             "Application should try to receive a packet, but then timeout")

    # case2 ping for ip:10.10.1.254 and dst mac are known but src didn't send reply
    req_ping = mk_ping("22:00:00:00:00:00", 'ff:ff:ff:ff:ff:ff', '192.168.1.2',
                       '10.10.1.254')
    s.expect(PacketInputEvent('router-eth0', req_ping, display=IPv4),
             "send A ping request to 10.10.1.254 arrive on router-eth0")
    req_ping = mk_ping('10:00:00:00:00:02',
                       '11:00:00:00:00:00',
                       '192.168.1.2',
                       '10.10.1.254',
                       reply=False,
                       ttl=63)
    s.expect(
        PacketOutputEvent('router-eth1', req_ping, display=IPv4),
        "forward 192.168.1.2 to 10.10.1.254 ping request leave out on router-eth1"
    )
    rep_ping = mk_ping("11:00:00:00:00:00", "10:00:00:00:00:02", "10.10.1.254",
                       '192.168.1.2', True)
    s.expect(
        PacketInputEvent('router-eth1', rep_ping, display=IPv4),
        "10.10.1.254 send ping reply to 192.168.1.2 arrive on router-eth1")
    req_arp = mk_arpreq("10:00:00:00:00:01", "192.168.1.1", "192.168.1.2")
    s.expect(PacketOutputEvent('router-eth0', req_arp, display=Arp),
             "send Arp request for 192.168.1.2 leave out on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.5),
             "Application should try to receive arp reply, but then timeout")
    s.expect(PacketOutputEvent('router-eth0', req_arp, display=Arp),
             "send Arp request for 192.168.1.2 leave out on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.5),
             "Application should try to receive arp reply, but then timeout")
    s.expect(PacketOutputEvent('router-eth0', req_arp, display=Arp),
             "send Arp request for 192.168.1.2 leave out on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.5),
             "Application should try to receive arp reply, but then timeout")
    s.expect(PacketOutputEvent('router-eth0', req_arp, display=Arp),
             "send Arp request for 192.168.1.2 leave out on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.5),
             "Application should try to receive arp reply, but then timeout")
    s.expect(PacketOutputEvent('router-eth0', req_arp, display=Arp),
             "send Arp request for 192.168.1.2 leave out on router-eth0")

    # case3 ping which src and dst mac both known
    otroarp = mk_arpreq("10:00:00:00:00:03", "172.16.42.1", "172.16.42.2")
    otroarpresponse = mk_arpresp(otroarp, "33:00:00:00:00:00")
    s.expect(
        PacketInputEvent("router-eth2", otroarpresponse, display=Arp),
        "Router should receive an unsolicited ARP response for 172.16.42.2 on router-eth1 and prepare send the ping request to 10.10.1.254"
    )
    req_ping = mk_ping('33:00:00:00:00:00', '10:00:00:00:00:03', '172.16.42.2',
                       '10.10.1.254')
    s.expect(PacketInputEvent("router-eth2", req_ping, display=IPv4),
             '172.16.42.2 ping for 10.10.1.254 arrive on router-eth2')
    req_ping = mk_ping('10:00:00:00:00:02',
                       '11:00:00:00:00:00',
                       '172.16.42.2',
                       '10.10.1.254',
                       ttl=63)
    s.expect(PacketOutputEvent("router-eth1", req_ping, display=IPv4),
             '172.16.42.2 ping for 10.10.1.254 leave out on router-eth1')
    rep_ping = mk_ping('11:00:00:00:00:00',
                       '10:00:00:00:00:02',
                       '10.10.1.254',
                       '172.16.42.2',
                       reply=True)
    s.expect(PacketInputEvent("router-eth1", rep_ping, display=IPv4),
             '10.10.1.254 response for 172.16.42.2 arrive on router-eth1')
    rep_ping = mk_ping('10:00:00:00:00:03',
                       '33:00:00:00:00:00',
                       '10.10.1.254',
                       '172.16.42.2',
                       reply=True,
                       ttl=63)
    s.expect(PacketOutputEvent("router-eth2", rep_ping, display=IPv4),
             '10.10.1.254 response for 172.16.42.2 leave out on router-eth2')
    
    
    return s


write_table()
scenario = router_stage2()
