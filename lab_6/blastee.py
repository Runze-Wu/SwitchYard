#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time
from struct import *


def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    ip_mac = {
        "192.168.100.1": "10:00:00:00:00:01",
        "192.168.200.1": "20:00:00:00:00:01"
    }
    port_mac = {
        "blaster-eth0": "10:00:00:00:00:01",
        "blastee-eth0": "20:00:00:00:00:01",
        "middlebox-eth0": "40:00:00:00:00:01",
        "middlebox-eth1": "40:00:00:00:00:02"
    }
    while True:
        gotpkt = True
        try:
            timestamp, dev, pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
            if pkt[Ethernet].ethertype != EtherType.IPv4:
                continue
            if str(pkt[IPv4].dst) != "192.168.200.1":
                log_info("the dst ipaddr isn't blastee")
                return
            blastee_params = open("blastee_params.txt", 'r')
            line = blastee_params.read().strip().split()
            if len(line) == 4:
                blaster_ip, num = line[1], line[3]
            blastee_params.close()
            eth_header = Ethernet(src=port_mac["blastee-eth0"],
                                  dst=port_mac["middlebox-eth0"],
                                  ethertype=EtherType.IPv4)
            ip_header = IPv4(src="192.168.200.1",
                             dst=blaster_ip,
                             protocol=IPProtocol.UDP,
                             ttl=10)
            udp_header = UDP(src=6666, dst=7777)
            seq_num = RawPacketContents(pkt[RawPacketContents].to_bytes()[:4])
            payload_len = unpack(">H",
                                 pkt[RawPacketContents].to_bytes()[4:6])[0]
            print("ack pkt: " + str(unpack(">i", seq_num.to_bytes())[0]))
            add_payload = RawPacketContents(
                pkt[RawPacketContents].to_bytes()[6:14] +
                (bytes(8 - payload_len) if payload_len < 8 else bytes(0)))
            ack_packet = eth_header + ip_header + udp_header + seq_num + add_payload
            net.send_packet("blastee-eth0", ack_packet)
    net.shutdown()
