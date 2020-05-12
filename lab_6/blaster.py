#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time
from struct import *


def create_seq_packet(seq_num, port_mac, length):
    eth_header = Ethernet(src=port_mac["blaster-eth0"],
                          dst=port_mac["middlebox-eth1"],
                          EtherType=EtherType.IP)
    ip_header = IPv4(src="192.168.100.1",
                     dst="192.168.200.1",
                     protocol=IPProtocol.UDP)
    udp_header = UDP(src=7777, dst=6666)
    rawpkt = RawPacketContents(
        pack('>I', seq_num) + pack('>H', length) + bytes(length))
    return eth_header + ip_header + udp_header + rawpkt


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
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
    begin_time = timer = time.time()  #record whole time and timer counter
    LHS = RHS = 1  #left right boarder
    blaster_params = open("blaster_params.txt", 'r')
    line = blaster_params.read().strip().split()
    if len(line) == 12:
        blastee_ip, num, length = line[1], line[3], line[5]
        sender_window, timeout, recv_timeout = line[7], line[9], line[11]
    blaster_params.close()
    send_list = set()  #waiting for ack
    pkt_fifo = range(1, num + 1)
    pkt_send_count=[0]*(num+1)
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp, dev, pkt = net.recv_packet(timeout=recv_timeout)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            ack_seq = unpack('>i', pkt[RawPacketContents].to_bytes()[:4])
            if ack_seq in send_list:
                send_list.remove(ack_seq)
            LHS += (ack_seq == LHS)
        else:
            log_debug("Didn't receive anything")
            '''
            judge if time delay occur
            '''
            if time.time() - timer >= timeout:
                pkt_fifo = list(set(pkt_fifo.extend(send_list))).sort()
                timer = time.time()
        if len(send_list) == 0 and len(pkt_fifo) == 0:
            '''already done'''
            log_info("total time is {}".format(time.time()-begin_time))
            log_info("send packet num is {}".format(sum(pkt_send_count)))
            re_sent=once_sent=0
            for item in pkt_send_count:
                if item==1:once_sent+=1
                else: re_sent+=item
            log_info("resent num : {} only once num : {}".format(re_sent,once_sent))
        if RHS - LHS + 1 > sender_window: pass
        else:
            pkt = create_seq_packet(pkt_fifo[0])
            send_list.add(pkt_fifo[0])
            pkt_send_count[pkt_fifo[0]]+=1
            pkt_fifo.pop(0)
            net.send_packet("middlebox-eth1", pkt)
    net.shutdown()
