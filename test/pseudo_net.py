'''
Created on 2018年5月22日

@author: heguofeng
'''
from _thread import start_new_thread
import threading
import time
import random
import logging
from pp_link import NAT_TYPE


# def set_debug(debug_level=logging.INFO, filename="", debug_filter=lambda record:True):
#     console = logging.StreamHandler()
#     console_filter = logging.Filter()
#     console_filter.filter = debug_filter
#     console.addFilter(console_filter)
#     if filename:
#         logging.basicConfig(level=debug_level,
#                 format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
#                 datefmt='%Y/%m/%d %H:%M:%S',
# #                 datefmt='%a, %d %b %Y %H:%M:%S',
#                 filename=filename,
#                 filemode='w',
#                 )
#     else:
#         logging.basicConfig(level=debug_level,
#                 format='%(asctime)s %(filename)s[%(lineno)d] %(levelname)s %(message)s',
#                 datefmt='%Y/%m/%d %H:%M:%S',
#                 handlers = [console,]
#                 )


class NAT(object):

    def __init__(self, ip, port, nat_type):
        self.ip = ip
        self.port = port
        self.nat_type = nat_type
        self.map_table = {}
        self.idle = 180
        start_new_thread(self.timer, ())

    def out(self, dest_ip, dst_port):
        self.idle = 0
        if self.nat_type == NAT_TYPE["Turnable"]:
            self.map_table[(dest_ip, dst_port)] = ((self.ip, self.port), 1)
            return (self.ip, self.port)
        else:
            if (dest_ip, dst_port) not in self.map_table:
                self.map_table[(dest_ip, dst_port)] = ((self.ip, random.randint(10000, 60000)), 1)
            return self.map_table[(dest_ip, dst_port)][0]

    def in_(self, src_ip, src_port):
#         print(self.map_table)
        if self.nat_type == NAT_TYPE["Turnable"]:
            if self.idle < 180:
                return src_ip, src_port
        elif (src_ip, src_port) in self.map_table:
            return self.map_table[(src_ip, src_port)][0]
        else:
            return None, None

    def inaddrs(self):
        addrs = {}
        if self.nat_type == NAT_TYPE["Turnable"]:
            if self.idle < 180:
#                 print("return self ip",[(self.ip,self.port)])
                return {(self.ip, self.port):(self.ip, self.port)}
        else:
            map_table = self.map_table.copy()
            for (src_ip, src_port) in list(map_table.keys()):
                addrs[map_table[(src_ip, src_port)][0]] = (src_ip, src_port)
            return addrs
        return addrs

    def timer(self):
        self.idle += 3
        for key in list(self.map_table.keys()):
            self.map_table[key] = (self.map_table[key][0], self.map_table[key][1] + 3)
            if self.map_table[key][1] > 90:
                del self.map_table[key]
        threading.Timer(3, self.timer).start()


class FakeNet(object):
    '''
    2nd way to simulate,is more lower layer:

        self.fake_net = FakeNet()
        self.stationA = self.fake_net.fake(PPLinker(config={"node_id":100, "node_ip":"118.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]}))
        self.stationA.start()
    '''

    def __init__(self, node_id=0):

        self.buffer = {}
        start_new_thread(self.timer, ())

    def send(self, addr, data, nat):
        '''
        self.stationA.send = lambda peer,data: self.fake_net.send(peer,data,addr)
        '''
        outaddr = nat.out(addr[0], addr[1])
        if addr not in self.buffer:
            self.buffer[addr] = []

        self.buffer[addr].append(((data, outaddr), int(time.time())))
#         logging.debug("send %s data %s on %s"%("%s:%d"%addr,data[:2],"%s:%d"%outaddr))
#         print(self.buffer)

    def receive(self, node_id=0, nat=None):
        '''
        self.stationA._receive = lambda : self.fake_net.receive(100)
        '''
        dst_addrs = nat.inaddrs()
        for dst_addr in list(dst_addrs.keys()):
            if dst_addr in self.buffer and self.buffer[dst_addr]:
#                 logging.debug("receive:%s %s"%self.buffer[dst_addr][0][0])
                try:
                    data, addr = self.buffer[dst_addr].pop(0)[0]
                    if addr == dst_addrs[dst_addr] or dst_addrs[dst_addr] == dst_addr:
                        return data, addr
                    else:
                        print("drop packet for can't in.")
                except Exception as exp:
                    logging.debug(exp)
                    return None,None
        return None, None

    def timer(self):
        now = time.time()
        for dst_addr in list(self.buffer.keys()):
            for msg in list(self.buffer[dst_addr]):
                index = self.buffer[dst_addr].index(msg)
                if now - self.buffer[dst_addr][index][1] > 20:
                    del self.buffer[dst_addr][index]
            if not self.buffer[dst_addr]:
                del self.buffer[dst_addr]
        threading.Timer(60, self.timer).start()

    def fake(self,station):
        nat = NAT(station.ip,station.port,station.nat_type)
        logging.info("fake %d network %s %d %d"%(station.node_id,station.ip,station.port,station.nat_type))
        station._send = lambda addr,data: self.send(addr,data,nat)
        station._receive = lambda : self.receive(station.node_id,nat)
        return station

