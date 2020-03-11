'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    forward_table=dict()
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        now_time=time.time()
        for key,value in list(forward_table.items()):
            if now_time-value[1]>=10.0:
                log_info("del {}:{}".format(key,value))
                forward_table.pop(key)
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug("Packet intended for me")
        else:
            src_mac=str(packet[Ethernet].src)
            dst_mac=str(packet[Ethernet].dst)
            log_info('from {} to {}'.format(src_mac,dst_mac))
            forward_table[src_mac]=(input_port,now_time)
            if dst_mac in forward_table.keys():
                log_debug('packet {} to {}'.format(packet,forward_table.get(dst_mac)[0]))
                net.send_packet(forward_table.get(dst_mac)[0],packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
