import unittest

from ppnet.config import PP_APPID
from ppnet.ppbeater import Beater
from ppnet.ppl2node import PPMessage, PPApp
from ppnet.ppl3node import Peers


class MyTestCase(unittest.TestCase):
    def test_PPMessage(self):
        origin_dict = {"app_id": 5, "app_data": b"1234", "src_id": b"1234", "dst_id": b"1235"}
        pm = PPMessage(dictdata=origin_dict)
        bindata = pm.dump()
        pm2 = PPMessage(bindata=bindata)
        self.assertEqual(pm2.get("app_id"), origin_dict["app_id"])
        self.assertEqual(pm2.get("app_data"), origin_dict["app_data"])

    def test_AppMessage(self):
        origin_dict = {"parameters": {"filename": b"test.txt"}, "command": "send"}
        tags_id = {"filename": 10, "send": 1}
        parameters_type = {1: "str", "start": "H"}
        pm = PPApp.AppMessage(app_id=5, tags_id=tags_id, parameters_type=parameters_type,
                              dictdata=origin_dict)
        bindata = pm.dump()
        pm2 = PPApp.AppMessage(app_id=5, tags_id=tags_id, parameters_type=parameters_type,
                               bindata=bindata)
        self.assertEqual(pm2.app_id, 5)
        self.assertEqual(pm2.get_parameter("filename"), origin_dict["parameters"]["filename"])
        self.assertEqual(pm2.get_command(), origin_dict["command"])

    def test_BeatMessage(self):
        origin_dict = {"parameters": {"timestamp": 123}, "command": "beat_req"}
        pm = Beater.BeatMessage(dictdata=origin_dict)
        bindata = pm.dump()
        pm2 = Beater.BeatMessage(bindata=bindata)
        self.assertEqual(pm2.app_id, PP_APPID["Beat"])
        self.assertEqual(pm2.get_parameter("timestamp"), origin_dict["parameters"]["timestamp"])
        self.assertEqual(pm2.get_command(), origin_dict["command"])

    def ttest_LoadDumpNode(self):
        peers = Peers()
        nodes = {100: {"node_id": 100, "ip": "180.153.152.193", "port": 54330, "secret": "", },
                 201: {"node_id": 201, "ip": "116.153.152.193", "port": 54330, "secret": "", },
                 202: {"node_id": 202, "ip": "116.153.152.193", "port": 54320, "secret": "", }}
        peers.set_nodes(nodes)
        nodes1 = peers.dump_nodes()
        self.assertDictEqual(nodes, nodes1, "test_DumpNode")
        peers.load_nodes({"node_file": "nodes.pkl"})
        nodes2 = peers.dump_nodes()
        self.assertDictEqual(nodes, nodes2, "test_LoadNode")
        pass


def test_PPApp(self):
    self.assertEqual(True, True)


if __name__ == '__main__':
    unittest.main()
