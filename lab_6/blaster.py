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
                          ethertype=EtherType.IPv4)
    ip_header = IPv4(src="192.168.100.1",
                     dst="192.168.200.1",
                     protocol=IPProtocol.UDP,
                     ttl=10)
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
        blastee_ip, num, length = line[1], int(line[3]), int(line[5])
        sender_window, timeout, recv_timeout = int(line[7]), int(line[9]), int(
            line[11])
    blaster_params.close()
    send_list = set()  #waiting for ack
    pkt_fifo = list(range(1, num + 1))
    pkt_send_count = [0] * (num + 1)
    re_sent = once_sent = timeout_count = 0
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp, dev, pkt = net.recv_packet(timeout=(recv_timeout) /
                                                  1000)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            if pkt[Ethernet].ethertype != EtherType.IPv4:
                continue
            ack_seq, = unpack('>i', pkt[RawPacketContents].to_bytes()[:4])
            if ack_seq in send_list:
                send_list.remove(ack_seq)
            if ack_seq == LHS:
                timer = time.time()  #restart the timer
                if len(send_list) != 0:
                    LHS = sorted(list(send_list))[0]
                elif len(pkt_fifo) != 0:
                    LHS = pkt_fifo[0]
                else:
                    LHS = num + 1
            print("got ack {} LHS: {} RHS: {}".format(ack_seq, LHS, RHS))
        else:
            log_debug("Didn't receive anything")
            '''
            judge if time delay occur
            '''
            if time.time() - timer >= (timeout) / 1000:
                print("timeout meet {} {}".format(time.time(),timer))
                timeout_count += 1
                pkt_fifo.extend(send_list)  #add already send but no ack pkt
                pkt_fifo = sorted(list(set(pkt_fifo)))
                timer = time.time()  #restart the timer

        if LHS == num + 1:
            '''already done'''
            duration, fullpkt = time.time() - begin_time, sum(pkt_send_count)
            #print("send case {}".format(pkt_send_count[1:]))
            for item in pkt_send_count[1:]:
                if item == 1: once_sent += 1
                else: re_sent += (item - 1)
            full, good = fullpkt * length, num * length
            log_info("Total TX time: {:.3f}s".format(duration))
            log_info("Number of reTX: {}".format(re_sent))
            log_info("Number of coarse TOs: {}".format(timeout_count))
            log_info("Throughput: {:.3f}Bps".format(full / duration))
            log_info("Goodput: {:.3f}Bps".format(good / duration))
            break

        if len(pkt_fifo) == 0: continue
        if pkt_fifo[0] not in send_list:
            if RHS - LHS + 1 <= sender_window:
                RHS = pkt_fifo[0]
            else:
                print("window is full")
                continue
            print("send pkt: {} LHS: {} RHS: {}".format(pkt_fifo[0], LHS, RHS))
        else:
            print("resend pkt: " + str(pkt_fifo[0]))
        pkt = create_seq_packet(pkt_fifo[0], port_mac, length)
        send_list.add(pkt_fifo[0])
        pkt_send_count[pkt_fifo[0]] += 1
        pkt_fifo.pop(0)
        net.send_packet("blaster-eth0", pkt)

    net.shutdown()
