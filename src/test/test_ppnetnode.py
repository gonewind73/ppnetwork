import unittest

from ppnet.config import NAT_TYPE, PP_APPID
from ppnet.common import set_debug
from ppnet.ppbeater import Beater
from ppnet.ppl2node import PPL2Node, PPMessage
from ppnet.ppl3node import PPL3Node
from ppnet.ppl4node import PPDataer, PPDataNode
from test.mocknet import MockNet
import time
import logging

#
# class TTestL2(unittest.TestCase):
#     inited = 0
#     def start(self):
#         set_debug(logging.DEBUG)
#         self.stationA = PPL2Node(config={"node_id":b"PPSTA1", "node_ip":"118.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]})
#         self.stationB = PPL2Node(config={"node_id":b"PPSTA2", "node_ip":"116.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]})
#         self.stationC = PPL2Node(config={"node_id":b"PPSTA3", "node_ip":"116.153.152.193", "node_port":54320, "nat_type":NAT_TYPE["Turnable"]})
#
#         self.stationA.set_underlayer(MockNet(self.stationA))
#         self.stationB.set_underlayer(MockNet(self.stationB))
#         self.stationC.set_underlayer(MockNet(self.stationC))
#         # self.mock_net = MockNet()
#         # self.mock_net.mock(self.stationA)
#         # self.mock_net.mock(self.stationB)
#         # self.mock_net.mock(self.stationC)
#         self.inited = 1
#
#     def setUp(self):
#         if self.inited == 0:
#             self.start()
#         pass
#
#     def tearDown(self):
#         pass
#
#     def testL2Node(self):
#         self.assertEqual(self.stationA.node_id, b"PPSTA1")
#         self.assertEqual(self.stationB.node_id, b"PPSTA2")
#         self.assertEqual(self.stationC.node_id, b"PPSTA3")
#
#     def ack_callback(self,peer_id,sequence,status):
#         print(peer_id,sequence,status)
#         self.ackResult = status
#
#     def testAckor(self):
#         # self.stationA = self.mock_net.mock(PPL2Node(config={"node_id":b"100", "node_ip":"118.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]},
#         #                                             ack_callback=self.ack_callback ))
#         self.ackResult = False
#         self.stationA.services[PP_APPID["Ack"]].set_callback(self.ack_callback)
#         dictdataA={"src_id":b"PPSTA1","dst_id":b"PPSTA2",
#                    "app_data":b"app_data",
#                    "app_id":7}
#         self.stationA.start()
#         self.stationB.start()
#         # to have a hole
#         dictdataB={"src_id":b"PPSTA2","dst_id":b"PPSTA3",
#                    "app_data":b"app_data",
#                    "app_id":7}
#         self.stationB.send_ppmsg_peer(PPMessage(dictdata=dictdataB),self.stationC)
#         self.stationA.send_ppmsg_peer(PPMessage(dictdata=dictdataA),self.stationB,  need_ack=True)
#
#         time.sleep(1)
#         self.assertTrue(self.ackResult, "test Ackor")
#         self.stationA.quit()
#         self.stationB.quit()
#


class TestL3(unittest.TestCase):
    '''
    todo：多个测试时会出现 duplication message，怀疑和多线程测试有关，
    '''

    def start(self):
        # set_debug(logging.INFO)

        self.addrA = ("118.153.152.193",54330)
        self.addrB = ("118.153.152.193",54320)
        self.addrC = ("118.153.152.193",54321)
        self.nodeinfoA = {"node_id":b"PPSTA1", "node_ip":self.addrA[0], "node_port":self.addrA[1], "nat_type":NAT_TYPE["Turnable"],"secret":"password"}
        self.nodeinfoB = {"node_id":b"PPSTA2", "node_ip":self.addrB[0], "node_port":self.addrB[1], "nat_type":NAT_TYPE["Turnable"],"secret":"password"}
        self.nodeinfoC = {"node_id":b"PPSTA3", "node_ip":self.addrC[0], "node_port":self.addrC[1], "nat_type":NAT_TYPE["Turnable"],"secret":"password"}
        self.stationA = PPL3Node(config=self.nodeinfoA)
        self.stationB = PPL3Node(config=self.nodeinfoB)
        self.stationC = PPL3Node(config=self.nodeinfoC)
        time_scale =1
        self.stationA.beater.time_scale = time_scale
        self.stationB.beater.time_scale = time_scale
        self.stationC.beater.time_scale = time_scale

        self.stationA.set_underlayer(MockNet(self.stationA))
        self.stationB.set_underlayer(MockNet(self.stationB))
        self.stationC.set_underlayer(MockNet(self.stationC))
        self.nodes=[(b"PPSTA1", self.addrA[0],self.addrA[1],NAT_TYPE["Turnable"]),
               (b"PPSTA2", self.addrB[0],self.addrB[1],NAT_TYPE["Turnable"]),
               (b"PPSTA3", self.addrC[0],self.addrC[1],NAT_TYPE["Turnable"]),]
        TestL3.inited = 1

    def setUp(self):
        self.start()
        pass

    def tearDown(self):
        # self.stationA.quit()
        # self.stationB.quit()
        # self.stationC.quit()
        pass

    def ttestNode(self):
        self.assertEqual(self.stationA.node_id, b"PPSTA1")
        self.assertEqual(self.stationB.node_id, b"PPSTA2")
        self.assertEqual(self.stationC.node_id, b"PPSTA3")

    def ack_callback(self,peer_id,sequence,status):
        print(peer_id,sequence,status)
        self.ackResult = status

    def ttestBeatnull(self):
        self.stationA.beater.beat_null()
        self.stationB.beater.beat_null()
        self.stationC.beater.beat_null()
        self.assertTrue(self.stationA.underlayer.nat.inaddrs())

    def ttestAckor(self):
        # self.stationA = self.mock_net.mock(PPL2Node(config={"node_id":b"100", "node_ip":"118.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]},
        #                                             ack_callback=self.ack_callback ))
        print("======start ackor========================================")
        self.ackResult = False
        self.stationA.services[PP_APPID["Ack"]].set_callback(self.ack_callback)

        bt_dictdata = {
            "command":"beat_req",
            "parameters":{
                "net_id":1,
                "node":self.nodeinfoA,
                "peer":self.nodeinfoB,
                "timestamp":int(time.time()),
            }
        }
        bm = Beater.BeatMessage(dictdata=bt_dictdata)
        dictdataA={"src_id":b"PPSTA1","dst_id":b"PPSTA2",
                   "app_data":bm.dump(),
                   "app_id":7}
        self.stationA.start()
        self.stationB.start()

        # to have a hole
        dictdataB={"src_id":b"PPSTA2","dst_id":b"PPSTA3",
                   "app_data":b"app_data",
                   "app_id":7}
        self.stationB.send_ppmsg_peer(PPMessage(dictdata=dictdataB),self.stationC)
        self.stationA.send_ppmsg_peer(PPMessage(dictdata=dictdataA),self.stationB,  need_ack=True)

        time.sleep(1)
        self.assertTrue(self.ackResult, "test Ackor")
        self.stationA.quit()
        self.stationB.quit()
        time.sleep(2)
        print("======end ackor========================================")

    def ttestBeat(self):
        print("======start beat========================================")
        # self.stationA.underlayer.clear()
        speedup=0.01
        self.stationA.beater.time_scale = speedup
        self.stationB.beater.time_scale = speedup
        self.stationC.beater.time_scale = speedup
        self.stationA.start()
        self.stationB.start()
        self.stationC.start()

        self.assertTrue(self.stationA.status==False,"StationA offline")
        self.assertTrue(self.stationB.status==False,"StationA offline")
        self.assertTrue(self.stationC.status==False,"StationA offline")
        self.stationB.set_nodes(self.nodes)
        time.sleep(2)
        self.assertTrue(self.stationA.status,"StationA online")
        self.assertTrue(self.stationB.status,"StationB online")
        self.assertTrue(self.stationC.status,"StationC online")
        self.stationA.quit()
        self.stationB.quit()
        self.stationC.quit()
        print("======end beat========================================")

    def ttestPath(self):
        self.stationA.underlayer.clear()
        self.stationA.set_nodes(self.nodes[:2])
        self.stationA.start()
        self.stationB.set_nodes(self.nodes[1:])
        self.assertTrue(self.stationC.status==False,"StationC offline")
        self.stationB.start()
        self.stationC.start()
        # self.stationB.beater.beat()
        time.sleep(10)
        # self.assertTrue(self.stationC.status,"StationC online")
        self.stationA.pather.request_path(b"PPSTA3")
        time.sleep(2)
        self.assertEqual(self.stationA.get_node_path(b"PPSTA3"),[b"PPSTA3"],"Find StationC Path")
        # self.assertEqual(self.stationA.get_status(b"PPSTA3"),True,"Find StationC Path 2")
        print(self.stationA.get_node_path(b"PPSTA3"))
        print(self.stationC.get_node_path(b"PPSTA1"))
        time.sleep(5)
        self.stationA.quit()
        self.stationC.quit()
        self.stationB.quit()

    def ttestData(self):
        self.stationA.underlayer.clear()
        self.stationB.set_nodes(self.nodes)
        self.stationA.set_nodes(self.nodes)
        self.stationC.set_nodes(self.nodes)
        self.stationB.start()
        self.stationA.start()
        self.stationC.start()
        time.sleep(1)
        self.stationA.set_node_path(b"PPSTA3",[[b"PPSTA2"],[b"PPSTA3"]])
        self.stationC.set_node_path(b"PPSTA1",[[b"PPSTA2"],[b"PPSTA1"]])
        # self.stationA.pather.request_path(b"PPSTA3")
        time.sleep(1)
        dataerC = PPDataer()
        dataerC.set_underlayer(self.stationC)
        dataerA = PPDataer()
        dataerA.set_underlayer(self.stationA)
        dataerC.send(b"testdata",self.addrA)
        data,addr = dataerA.receive(5)
        time.sleep(2)
        self.assertEqual(data,b"testdata","Test Dataer")
        self.assertEqual(addr,self.addrC,"Test Dataer")
        dataerA.quit()
        dataerC.quit()
        self.stationB.quit()

    def testDataNode(self):
        datanodeA = PPDataNode(config=self.nodeinfoA)
        datanodeB = PPDataNode(config=self.nodeinfoB)
        self.assertTrue(True,"test datanode. ")



if __name__ == '__main__':
    unittest.main()
