'''
Created on 2018年5月22日

@author: heguofeng
'''
import unittest
from pp_link import PPLinker, NAT_TYPE, PPMessage, set_debug
from test.pseudo_net import FakeNet
import logging
import time


class TestLinker(unittest.TestCase):
    inited = 0

    def start(self):

        self.stationA = PPLinker(config={"node_id":100, "node_ip":"118.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]}) 
        self.stationB = PPLinker(config={"node_id":201, "node_ip":"116.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]})
        self.stationC = PPLinker(config={"node_id":202, "node_ip":"116.153.152.193", "node_port":54320, "nat_type":NAT_TYPE["Turnable"]})

        self.fake_net = FakeNet()
        self.fake_net.fake(self.stationA)
        self.fake_net.fake(self.stationB)
        self.fake_net.fake(self.stationC)     
        self.inited = 1

    def setUp(self):
        set_debug(logging.DEBUG, "")
        if self.inited == 0:
            self.start()
        pass

    def tearDown(self):
        pass

    def testPPMessage(self):
        dictdata={"src_id":12,"dst_id":13,
                    "app_data":b"app_data",
                    "app_id":7}
        ppmsg = PPMessage(dictdata=dictdata)
        bindata = ppmsg.dump()
        ppmsg1 = PPMessage(bindata=bindata)
        self.assertDictContainsSubset(dictdata, ppmsg1.dict_data,"test ppmessage")
        pass

    def ack_callback(self,peer_id,sequence,status):
        print(peer_id,sequence,status)
        self.ackResult = status

    def testAckor(self):
        self.stationA = self.fake_net.fake(PPLinker(config={"node_id":100, "node_ip":"118.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]},
                                                                                ack_callback=self.ack_callback ))
        self.ackResult = False
        dictdataA={"src_id":100,"dst_id":201,
                    "app_data":b"app_data",
                    "app_id":7}
        self.stationA.start()
        self.stationB.start()
        # to have a hole
        dictdataB={"src_id":201,"dst_id":202,
                    "app_data":b"app_data",
                    "app_id":7}
        self.stationB.send_ppmsg(self.stationC, PPMessage(dictdata=dictdataB))
        self.stationA.send_ppmsg(self.stationB, PPMessage(dictdata=dictdataA), need_ack=True)

        time.sleep(1)
        self.assertTrue(self.ackResult, "test Ackor")
        self.stationA.quit()
        self.stationB.quit()

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()