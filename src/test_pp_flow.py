'''
Created on 2018年5月22日

@author: heguofeng
'''
import unittest
from pp_link import set_debug, NAT_TYPE
import logging
from test.test_pp_control import FakeAppNet
from pp_control import Session
import time
from pp_flow import Flow

pseudo_sockets= {}    
class PseudoSock(object):
        def __init__(self,addr,peer=None):
            logging.debug("pseudo socket init")
            self.addr = addr
            self.peer = peer
            self.peers = {}
            self.buffer=[]
            pass
        
        def listen(self):
            pseudo_sockets[self.addr] = self
            
        
        def connect(self,addr):
            count = 0
            while  count <10 :
                if addr in pseudo_sockets:
                    pseudo_sockets[addr].peers.update({self.addr:self})
                    self.peers.update({addr:pseudo_sockets[addr]})
                    return self
                count+=1
                time.sleep(1)
            return None
            
        
        def accept(self):
            while self.peers:
                client_addr,client_sock = self.pop(0)
            return client_sock,client_addr    
        
        def send(self,data):
            list(self.peers.values())[0].buffer.append(data)
            pass
        
        def receive(self):
            count = 0
            while  count<10:
                if self.buffer:
                    return self.buffer.pop(0)
                count+=1
                time.sleep(1)
            return None
        
        @staticmethod
        def prepare_socket(timeout=10,ip="0.0.0.0",port=0):
            return PseudoSock((ip,port),None)


class TestFlow(unittest.TestCase):

    def setUp(self):
        set_debug(logging.DEBUG, "")
        self.nodes = {100: { "node_id": 100,"ip": "180.153.152.193", "port": 54330,"secret": "",},
             201: { "node_id": 201,"ip": "116.153.152.193", "port": 54330, "secret": "",},
             202:  { "node_id": 202,"ip": "116.153.152.193", "port": 54320,"secret": "",}}
        config={"node_ip":"180.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"],
                "nodes":self.nodes}
        config.update({'node_id':100,"node_ip":"180.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]})
        self.stationA = FakeAppNet(config)
        config.update({'node_id':201,"node_ip":"116.153.152.193","node_port":54330, "nat_type":NAT_TYPE["Turnable"]})
        self.stationB = FakeAppNet(config)
        
#         processes = {100:self.stationB.process,
#                      200:self.stationA.process}
#         self.stationA.set_process(processes)
#         self.stationB.set_process(processes)           
        pass

    def tearDown(self):

        pass
    def TtestSession(self):
        receive_buffer = ""
        send_buffer = ""
        def receive_process(session,data):
            nonlocal receive_buffer
            receive_buffer += data
        def send_process(session,data):
#             nonlocal send_buffer
#             send_buffer += data
            print(session,data)
            
        s = Session(send_process=send_process,
                          receive_process=receive_process)
        for i in range(10):
            session={"id":100,"size":0,"start":i,"end":i+1}
            print(s.send(session,str(i)))
            rsession={"id":100,"size":0,"start":9-i,"end":9-i+1}
            print(s.receive(rsession, str(9-i)))
        session={"id":100,"size":10,"start":10,"end":10}
        print(s.send(session, "end"))
        print(s.receive(session, "end"))
        print(send_buffer,receive_buffer)
        self.assertEqual(receive_buffer, "0123456789", "test session")
        self.assertEqual(s.receive_size, 10, "test session")
        self.assertEqual(s.send_size, 10, "test session")

        
    def testFlow(self):
        prepare_socket = PseudoSock.prepare_socket
        self.client = Flow(self.stationA,config={"flow_port":7200})
        self.server = Flow(self.stationB,config={"flow_port":7300})
        processes = {100:self.client.process,
                     201:self.server.process}
        self.stationA.set_process(processes)
        self.stationB.set_process(processes)          
        self.client.start()
        self.server.start()
        time.sleep(30)
        session = self.client.connect(201, session=None)
        print(session,self.client.sessions)
        self.client.quit()
        self.server.quit()
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()