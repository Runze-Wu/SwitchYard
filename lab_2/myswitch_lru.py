'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    forward_table,max_len=list(),5
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug("Packet intended for me")
        else:
            src_mac,dst_mac=str(packet[Ethernet].src),str(packet[Ethernet].dst)
            log_debug('from {} to {}'.format(src_mac,dst_mac))
            src_flag,dst_flag=False,False 
            for i in range(len(forward_table)):
                if forward_table[i][0]==src_mac:
                    sr_flag,forward_table[i][1]=True,input_port
                    break
            if src_flag==False:
                if len(forward_table)==max_len:
                    forward_table.pop()
                forward_table.insert(0,[src_mac,input_port])
            for i in range(len(forward_table)):
                if forward_table[i][0]==dst_mac:
                    dst_flag,dst_pair=True,forward_table[i]
                    forward_table.remove(forward_table[i])
                    forward_table.insert(0,dst_pair)
                    net.send_packet(dst_pair[1],packet)
                    break
            if dst_flag==False:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
