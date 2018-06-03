'''
Created on 2018年5月22日

@author: heguofeng
'''
from _thread import start_new_thread
import threading
import time
import random
import logging
from pp_link import NAT_TYPE, BroadCastId, PPMessage
from pp_control import PPStation

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
        station.testing = True
        return station


class FakeAppNet(PPStation):
    '''
    2way to simulate network
    
    1st way to simulate is for app tester
        station1 = FakeAppNet(node_id1)
        station2 = FakeAppNet(node_id2)
        ...
        processes ={node_id1:process1,node_id2:process2,...}
        station1.set_process(processes)
        station2.set_process(processes)   
        ...
             
        app runcode
    
    2nd way to simulate,is more lower layer，please use FakeNet:
    
        self.fake_net = FakeNet()
        
        self.stationA = self.fake_net.fake(PPLinker(config={"node_id":100, "node_ip":"118.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]}))
        self.stationA.start()
    '''
    def __init__(self, config):
        super().__init__(config)
#         self.node_id = node_id
#         self.process_list = {}
        self.process = {}
        self.status = True  # simulate net broken
#         self.quitting = False
        pass
    
#     def set_app_process(self, appid, app_process):
#         self.process_list[appid] = app_process
#         pass
    
    def set_process(self, process):
        '''
        processes ={node_id1:process1,node_id2:process2,...}
        '''
        self.process = process
        
    def send_msg(self, peer_id, app_msg, need_ack=False, always=False):
        if peer_id == BroadCastId:
            for peer in self.process:
#                 logging.debug(peer)
                self.send_msg(peer, app_msg, need_ack, always)
            return
        app_data = app_msg.dump()
        ppmsg = PPMessage(dictdata={"src_id":self.node_id, "dst_id":peer_id,
                                            "app_data":app_data, "app_len":len(app_data),
                                            "app_id":app_msg.get("app_id")})
        if self.status and not self.node_id == peer_id:
            self.process[peer_id](ppmsg, ("0.0.0.0", 54320))
        pass       
    
    def process_msg(self, ppmsg, addr):
        app_id = ppmsg.get("app_id")
        if app_id in self.process_list:
            self.process_list[app_id](ppmsg,addr)
        else:
            logging.warning("%d no process define for %d"%(self.node_id,app_id))

