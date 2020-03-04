#!/usr/bin/env python3
'''
Ethernet hub in Switchyard.
'''
from switchyard.lib.userlib import *


def main(net):
    in_count = 0
    out_count = 0
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    while True:
        try:
            timestamp, dev, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            continue

        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            in_count += 1
            for intf in my_interfaces:
                if dev != intf.name:
                    out_count+=1
                    log_info('{} in: {}> out: {}>'.format(timestamp,in_count,out_count))
                    # log_info ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf, packet)
    net.shutdown()
