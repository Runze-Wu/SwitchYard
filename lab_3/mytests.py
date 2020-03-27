#!/usr/bin/env python3

from switchyard.lib.userlib import *



def my_tests():
    s = TestScenario("router_arp_reply tests")
    s.add_interface('eth1', '10:00:00:00:00:00','1.0.0.0')
    s.add_interface('eth2', '20:00:00:00:00:00','2.0.0.0')
    s.add_interface('eth3', '30:00:00:00:00:00','3.0.0.0')
    #case1 ask 1.0.0.0's mac normal
    request_pkt = create_ip_arp_request('40:00:00:00:00:00','4.0.0.0','1.0.0.0')
    s.expect(PacketInputEvent('eth1',request_pkt),"request packet {} arrive on eth1".format(request_pkt))
    reply_pkt = create_ip_arp_reply('10:00:00:00:00:00', '40:00:00:00:00:00','1.0.0.0', '4.0.0.0')
    s.expect(PacketOutputEvent('eth1',reply_pkt),"reply packet {} forward to eth1".format(reply_pkt))
    #case2 ask ip which not in router
    request_pkt = create_ip_arp_request('40:00:00:00:00:00','4.0.0.0','5.0.0.0')
    s.expect(PacketInputEvent('eth1',request_pkt),"request packet {} arrive on eth1".format(request_pkt))
    s.expect(PacketInputTimeoutEvent(0.4),'the request dst ip 5.0.0.0 not in this router so nothing happen')
    #case3 packet type not request can't process
    p = Ethernet(src="00:11:22:33:44:55", dst="66:55:44:33:22:11") + IPv4(src="1.1.1.1", dst="2.2.2.2", protocol=IPProtocol.UDP) + UDP(src=5555, dst=8888)
    s.expect(PacketInputEvent('eth1', p),"A udp packet should arrive on eth1")
    s.expect(PacketInputTimeoutEvent(0.4),'the UDP packet current router can\'t process so nothing happen')
    #case4 ask 3.0.0.0's mac normal
    request_pkt = create_ip_arp_request('60:00:00:00:00:00','6.0.0.0','3.0.0.0')
    s.expect(PacketInputEvent('eth2',request_pkt),"request packet {} arrive on eth1".format(request_pkt))
    reply_pkt = create_ip_arp_reply('30:00:00:00:00:00', '60:00:00:00:00:00','3.0.0.0', '6.0.0.0')
    s.expect(PacketOutputEvent('eth2',reply_pkt),"reply packet {} forward to eth1".format(reply_pkt))
    return s


scenario = my_tests()
