from switchyard.lib.userlib import *
import time
from random import randint

class Rule(object):
    def __init__(self, items: dict):
        self.items = items
        self.perimit = items['permit']
        self.type = items['type']
        self.src = '0.0.0.0/0' if items['src'] == 'any' else items['src']
        self.dst = '0.0.0.0/0' if items['dst'] == 'any' else items['dst']
        self.src_port = items['srcport']
        self.dst_port = items['dstport']
        self.ratelimit = items['ratelimit']
        self.impair = items['impair']

    def __str__(self):
        return "{}".format(self.items)

    def __eq__(self, pkt):
        if pkt[Ethernet].ethertype != EtherType.IPv4:
            return False
        protocol, src, dst = pkt[IPv4].protocol, pkt[IPv4].src, pkt[IPv4].dst
        if not src in IPv4Network(self.src, strict=False): return False
        if not dst in IPv4Network(self.dst, strict=False): return False
        if protocol == IPProtocol.ICMP:
            if not (self.type == 'ip' or self.type == 'icmp'): return False
        elif protocol == IPProtocol.TCP:
            if not (self.type == 'ip' or self.type == 'tcp'): return False
            if not self.type == 'ip':
                src_port, dst_port = pkt[TCP].src, pkt[TCP].dst
                if not (self.src_port == 'any'
                        or int(self.src_port) == src_port):
                    return False
                if not (self.dst_port == 'any'
                        or int(self.dst_port) == dst_port):
                    return False
        elif protocol == IPProtocol.UDP:
            if not (self.type == 'ip' or self.type == 'udp'): return False
            if not self.type == 'ip':
                src_port, dst_port = pkt[UDP].src, pkt[UDP].dst
                if not (self.src_port == 'any'
                        or int(self.src_port) == src_port):
                    return False
                if not (self.dst_port == 'any'
                        or int(self.dst_port) == dst_port):
                    return False
        else:
            return False
        return True

def translate(cur_rule: list):
    items = dict()
    if len(cur_rule) == 0 or cur_rule[0][0] == '#':
        return (None,False)
    else:
        items['permit'] = True if 'permit' == cur_rule[0] else False
        items['type'] = cur_rule[1]
        items['srcport'], items['dstport'] = None, None
        items['ratelimit'], items['impair'] = None, False
        length = 10 if cur_rule[1] == 'udp' or cur_rule[1] == 'tcp' else 6
        for i in range(2, length, 2):
            items[cur_rule[i]] = cur_rule[i + 1]
        if 'ratelimit' == cur_rule[-2]:
            items[cur_rule[-2]] = cur_rule[-1]
        if 'impair' == cur_rule[-1]:
            items[cur_rule[-1]] = True
    return (items, True)

def init_rules():
    rules, token_bucket = list(), list()
    firewall_rules = open('firewall_rules.txt', 'r')
    for line in firewall_rules.readlines():
        line = line.strip().split()
        (items, legal) = translate(line)
        if legal:
            rules.append(Rule(items))
            if items['ratelimit'] != None:
                token_bucket.append(
                    [int(items['ratelimit']), 2 * int(items['ratelimit'])])
            else:
                token_bucket.append(None)
    firewall_rules.close()
    return rules, token_bucket


def judge_rule(pkt, rules):
    for i in range(0, len(rules)):
        if rules[i] == pkt:
            return i
    return -1


def token_get(pkt, rule, token_bucket):
    if token_bucket[rule] == None:
        return True
    pkt_size = len(pkt) - len(pkt.get_header(Ethernet))
    #log_info("{} pkt_size: {} rule: {}".format(pkt,pkt_size,rule+1))
    if token_bucket[rule][1] >= pkt_size:
        token_bucket[rule][1] = token_bucket[rule][1] - pkt_size
        return True
    else:
        return False


def impair_pkt(pkt):
    if pkt[Ethernet].ethertype != EtherType.IPv4:
        return pkt
    print("impair payload")
    if pkt.has_header(ICMP):
        pkt[ICMP].icmpdata.data=b'impaired'
    elif pkt.has_header(RawPacketContents):
        index = pkt.get_header_index(RawPacketContents)
        del pkt[index]
        pkt.insert_header(index,RawPacketContents(b'impaired'))
    else:pkt.add_payload(RawPacketContents(b'impaired'))
        
    '''joke = (randint(0, 3) if pkt[IPv4].protocol == IPProtocol.TCP else randint(
        0, 1))
    if joke==0 and randint(0, 100) < 10:print("drop pkt")
    elif joke==1:
        if pkt.has_header(RawPacketContents):
            print("impair payload")
            index = pkt.get_header_index(RawPacketContents)
            del pkt[index]
            pkt.insert_header(index,RawPacketContents(b'impaired'))
    elif joke == 2:
        pkt[TCP].window = 1
        print('impair tcp window')
    elif joke == 3 and randint(0, 100) < 5:
        pkt[TCP].RST = 1
        print('impair rst')'''

    return pkt


def main(net):
    # assumes that there are exactly 2 ports
    portnames = [p.name for p in net.ports()]
    portpair = dict(zip(portnames, portnames[::-1]))
    rules, token_bucket = init_rules()
    timer = time.time()

    while True:
        pkt = None
        try:
            timestamp, input_port, pkt = net.recv_packet(timeout=0.25)
        except NoPackets:
            pass
        except Shutdown:
            break

        if time.time() - timer >= 0.5:
            for i in range(len(token_bucket)):
                if token_bucket[i] != None:
                    token_bucket[i][1] = min(
                        token_bucket[i][0] * 2,
                        token_bucket[i][1] + token_bucket[i][0] / 2)
            timer = time.time()
            #print(token_bucket)
        if pkt is not None:
            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            match = judge_rule(pkt, rules)
            if match == -1:
                net.send_packet(portpair[input_port], pkt)
            elif rules[match].perimit:
                if token_bucket[match] != None:
                    if not token_get(pkt, match, token_bucket):
                        print("drop pkt")
                        continue
                elif rules[match].impair:
                    pkt = impair_pkt(pkt)
                net.send_packet(portpair[input_port], pkt)
    net.shutdown()
