'''
Created on 2018年5月22日

@author: heguofeng
'''
from pp_control import PPStation, Beater
from pp_link import BroadCastId, PPMessage, NAT_TYPE, set_debug
import logging
import unittest
from test.pseudo_net import FakeNet
import time

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


class TestControl(unittest.TestCase):

    inited = 0
    quiting = True

    def init(self):
        if self.inited == 1:
            return
        self.fake_net = FakeNet()
        self.nodes = {100: { "node_id": 100,"ip": "180.153.152.193", "port": 54330,"secret": "",},
                 201: { "node_id": 201,"ip": "116.153.152.193", "port": 54330, "secret": "",},
                 202:  { "node_id": 202,"ip": "116.153.152.193", "port": 54320,"secret": "",}}
        
        config={"node_id":100, "node_ip":"180.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"],
                                          "nodes":self.nodes,"ip":"0.0.0.0"}
        self.stationA = self.initStation(config) 
        config.update({"node_id":201, "node_ip":"116.153.152.193", "node_port":54330,"nat_type":NAT_TYPE["Unturnable"]})
        self.stationB = self.initStation(config)
        config.update({"node_id":202, "node_ip":"116.153.152.193", "node_port":54320})
        self.stationC = self.initStation(config)
        self.inited = 1

    def initStation(self,config):
        station = PPStation(config) 
        self.fake_net.fake(station)
#         station.beater.time_scale = 0.01
#         station.start()
        return station
    
    def start(self):
        if not self.inited:
            self.init()
        self.stationA.start()
        self.stationB.start()
        self.stationC.start()
        
    def quit(self):
        if self.inited:
            self.stationA.quit()
            self.stationB.quit()
            self.stationC.quit()
            self.inited = 0         

    def setUp(self):
        set_debug(logging.DEBUG, "",
                debug_filter=lambda record: record.filename =="pp_control.py"
                  )
        pass

    def tearDown(self):

        pass
    
    def test_LoadDumpNode(self):
        self.start()
        self.stationB.dump_nodes()
        nodes = self.stationB._dump_nodes_to_dict()
        self.stationB.load_nodes({"node_file":"nodes.pkl"})
        nodes1 = self.stationB._dump_nodes_to_dict()
        self.assertDictEqual(nodes, nodes1, "test_LoadDumpNode")
        self.quit()
        pass
    
    def test_BeatMessage(self):
        node_info = {"node_id":100,
                      "ip":"0.0.0.0",
                      "port":234,
                      "nat_type":5,
                      "will_to_turn":True,
                      "secret":"password"}
        dictdata = {
                    "command":"beat_req",
                    "parameters":{
                                  "net_id":1,
                                  "node":node_info,
                                  "peer":node_info,
                                  "timestamp":int(time.time()),
                                  }
                    }
        btmsg = Beater.BeatMessage(dictdata=dictdata)
        bin = btmsg.dump()
        btmsg2 = Beater.BeatMessage(bindata=bin)

        self.assertDictEqual(dictdata["parameters"]["node"], btmsg2.dict_data["parameters"]["node"], "test beatmessage")
        self.assertEqual(dictdata["command"], btmsg2.dict_data["command"], "test beatmessage")
        self.assertEqual(dictdata["parameters"]["net_id"], btmsg2.dict_data["parameters"]["net_id"], "test beatmessage")
        self.assertEqual(dictdata["parameters"]["timestamp"], btmsg2.dict_data["parameters"]["timestamp"], "test beatmessage")

#     @unittest.skip("command only")       
    def test_Beat(self):

        self.start()
        self.stationA.get_all_nodes(delay=0)
        self.stationB.get_all_nodes(delay=0)
        self.stationC.get_all_nodes(delay=0)    
        time.sleep(10)
        self.assertTrue(self.stationA.status, "Station A alive!")
        self.assertTrue(self.stationB.status, "Station B alive!")
        self.assertTrue(self.stationC.status, "Station C alive!")   
        self.stationA.get_all_nodes(delay=0)
        self.stationB.get_all_nodes(delay=0)
        self.stationC.get_all_nodes(delay=0)
        
        time.sleep(1)      

#     
#     def test_pathreq(self):
#         self.stationA.request_path(BroadCastId, 6)     
        self.stationB.path_requester.request_path(202, 6)    
#         self.stationC.request_path(BroadCastId, 6)      
        time.sleep(1)
        self.stationA.get_all_nodes(delay=0)
        self.stationB.get_all_nodes(delay=0)
        self.stationC.get_all_nodes(delay=0)   
        time.sleep(5)        
        self.assertEqual(self.stationA.nat_type,NAT_TYPE["Turnable"], "Station A nat_type!")
        self.assertEqual(self.stationB.nat_type,NAT_TYPE["Unturnable"], "Station B nat_type!")
        self.assertEqual(self.stationC.nat_type,NAT_TYPE["Unturnable"], "Station C nat_type!")
        self.assertEqual(self.stationB.peers[202].distance,2, "Station B distance to C!")
        self.assertEqual(self.stationC.peers[201].distance,2, "Station C distance to B!")  
          
#         self.stationB.send_beat(202)
        time.sleep(4)
        print("interal")
        time.sleep(2)
        self.quit()
        
    def test_getNodeId(self):
        self.start()
        config={"nodes":self.nodes}
        self.stationD = self.initStation(config)
        self.stationD.start()
        time.sleep(2)
        self.assertTrue(self.stationD.node_id, "test get node id")
                
    def test_getaddr(self):
        self.init()
        self.stationA.start()
        print("start get addr")
        self.stationB.node_id = 0
        self.stationB.start()
        
        try_count = 0
        while not self.stationB.node_id and try_count<10:
            self.stationB.beater.req_id()
            time.sleep(1)
            try_count += 1
        print(self.stationB.node_id,self.stationB.ip,self.stationB.port)
        self.assertTrue(self.stationB.node_id,"Test get addr ")  
        self.stationA.quit()
        self.stationB.quit()
        
    def text_callback(self, node_id, text):
        self.text = text
         
    def test_Text(self):
        self.start()        
        self.stationB.path_requester.request_path(202, 6)           
        time.sleep(7)
        self.stationA.texter.send_text(202, "test")
        self.stationA.texter.send_text(202, "test echo", echo=True,
                                callback=self.text_callback)
        time.sleep(1)     
        self.assertEqual(self.text, "test echo", "test text echo")
        self.quit()
        
    def test_netmanage(self):
        self.start()
        time.sleep(7)
        stat =  self.stationA.netmanage.get_stat(201)
        print(stat)
        self.assertTrue(stat["node_id"]==201, "test netmanage")
        self.assertTrue(stat["os"].find("Windows"),  "test netmanage")
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()        
