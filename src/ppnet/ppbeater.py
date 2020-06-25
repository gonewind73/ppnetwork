# coding=utf-8 
"""
Created on 2018年2月28日

@author: heguofeng

"""
import time
import socket
import threading
import struct
from _thread import start_new_thread
import logging
import traceback
import random

from ppnet.common import packaddr
from ppnet.ppl2node import PPApp, PPNode, PPMessage
from ppnet.config import BroadCastId, NAT_TYPE, NAT_STRING, PP_APPID


class Beater(PPApp):
    """
    beater功能：
    1、通知对方存在
    2、维护路由表

    定时发起beat流程
    1、发起beat_req
    2、等待beat_res
    3、保存最快路径

    收到beat_req:
    查看路径，是否
    """

    class BeatMessage(PPApp.AppMessage):
        """
        beat_cmd :1Byte   beatreq 0x01 beatres 0x02 beatset 0x03 offline 0x04
        paralen = 3
        parameters:
        net_id = TLV
        selfnode_info[node TLV]:
            node_id:      4Byte
            ip:           4Byte
            port:         2Byte
            nattype:      1Byte
            will_to_turn: 1Byte
            secret:       8Byte
        dstnode_info[peer TLV]:
            node_id:      4Byte
            ip:           4Byte
            port:         2Byte
            nattype:      1Byte
            will_to_turn: 1Byte
            secret:       8Byte
        timestamp: TLV   as beatseq

        dict_data={
                    command: "beat_req",
                    parameters:{

                        node: {node_id,ip,port,nat_type,will_to_turn,secret}
                        peer: {node_id,ip,port,nat_type,will_to_turn,secret}
                        beatseq:
                        error_info:
                        }

                    }
        beat_req  心跳请求
        beat_res  心跳响应。对请求进行响应，可以测试是否有链路可达
        beat_offline 下线，无应答
        """

        def __init__(self, **kwargs):
            tags_id = {
                "beat_req": 1, "beat_res": 2, "beat_set": 3, "offline": 4, "find_node": 5, "req_id": 6, "res_id": 7,
                "bin_node": 0x10, "bin_peer": 0x11, "bin_path": 0x15,
                "net_id": 0x12, "timestamp": 0x13, "error_info": 0x14}
            parameter_type = {0x10: "s", 0x11: "s", 0x15: "s",
                              0x12: "I", 0x13: "I", 0x14: "str"}
            super().__init__(app_id=PP_APPID["Beat"],
                             tags_id=tags_id,
                             tags_string=None,
                             parameter_type=parameter_type,
                             **kwargs)

        def load(self, bindata):
            if super().load(bindata) is None:
                return None
            #                 print(self.dict_data)
            if "bin_node" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["node"] = self._load_node(self.dict_data["parameters"]["bin_node"])
                del self.dict_data["parameters"]["bin_node"]
            if "bin_peer" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["peer"] = self._load_node(self.dict_data["parameters"]["bin_peer"])
                del self.dict_data["parameters"]["bin_peer"]
            if "bin_path" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["path"] = self._load_path(self.dict_data["parameters"]["bin_path"])
                del self.dict_data["parameters"]["bin_path"]
            return self

        def _load_node(self, bindata):
            node_info = {}
            result = struct.unpack("6sIHB8s", bindata)
            node_info["node_id"] = result[0]
            node_info["node_ip"] = socket.inet_ntoa(struct.pack('I', socket.htonl(result[1])))
            node_info["node_port"] = result[2]
            node_info["nat_type"] = result[3]
            node_info["secret"] = result[4].decode()
            return node_info

        def dump(self):
            if "node" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["bin_node"] = self._dump_node(self.dict_data["parameters"]["node"])
            if "peer" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["bin_peer"] = self._dump_node(self.dict_data["parameters"]["peer"])
            if "path" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["bin_path"] = self._dump_path(self.dict_data["parameters"]["path"])
            return super().dump()

        def _dump_node(self, node_info):
            return struct.pack("6sIHB8s",
                               node_info["node_id"],
                               socket.ntohl(struct.unpack("I", socket.inet_aton(node_info["node_ip"]))[0]),
                               node_info["node_port"],
                               node_info["nat_type"],
                               node_info["secret"].encode(), )

        def _load_path(self, bin_path, path_len):
            path = []
            for i in range(0, path_len):
                noderesult = struct.unpack("IIHB", bin_path[i * 11:i * 11 + 11])
                path.append((noderesult[0],
                             socket.inet_ntoa(struct.pack('I', socket.htonl(noderesult[1]))),
                             noderesult[2],
                             noderesult[3]))
            return path

        def _dump_path(self, path):
            data = b""
            for i in range(0, len(path)):
                node = path[i]
                nodedata = struct.pack("IIHB", node[0],
                                       socket.ntohl(struct.unpack("I", socket.inet_aton(node[1]))[0]),
                                       node[2], node[3])
                data += nodedata
            return data

    pass

    def __init__(self, station, callback=None):
        super().__init__(PP_APPID["Beat"], station, callback)
        self.beat_count = 0
        self.beat_interval = 1
        self.time_scale = 1

    def start(self):
        super().start()
        start_new_thread(self.beat, ())
        return self

    def beat(self):
        try:
            beated = False
            for peerid in self.station.peers:
                peer = self.station.peers[peerid]
                if peer.beat_interval > 3:
                    if peer.status:
                        logging.info("{0} : {1} is offline.".format(self.station.node_id, peerid))
                    peer.status = False
                    peer.distance = 10

                if self.beat_count % peer.beat_interval == 0:
                    peer.beat_interval = peer.beat_interval * 2 if peer.beat_interval < 65 else 128
                    self.send_beat(peerid, beat_cmd="beat_req")
                    if not self._is_private_ip(peer.ip):
                        beated = True

            if not beated:
                self.beat_null()
        except Exception as exp:
            logging.debug("{0}: beat exception {1}".format(self.station.node_id, exp))
            logging.debug(traceback.format_exc())
            pass

        self.beat_count += 1
        # if self.beat_count % 12*60 == 0:
        #     self.station.publish()

        if not self.quitting:
            self.timer = threading.Timer(60 * self.beat_interval * self.time_scale, self.beat)
            self.timer.start()
            self.no_beat = 0
            pass

    def rebeat(self):
        for peerid in self.station.peers:
            self.send_beat(peerid, beat_cmd="beat_req",is_try=True)
        pass

    def _direct_send(self, addr, dst_id, btmsg):
        msg = PPMessage(dictdata={"src_id": self.station.node_id,
                                  "dst_id": dst_id,
                                  "app_data": btmsg.dump(),
                                  "app_id": PP_APPID["Beat"],
                                  "sequence": 0xffffffff})
        self.station.send(msg, addr)

    def send_beat(self, peerid, beat_cmd="beat_req", is_try=False):
        if beat_cmd in ["offline"]:
            return self.send_offline()

        now = time.time()
        if peerid not in self.station.peers and not peerid == BroadCastId:
            logging.warning("{0} can't find {1},please try to find it first.".format(self.station.node_id, peerid))
            return False

        peer = self.station.peers[peerid]

        # todo 是否需要限制本机两个设备互访？取消影响了beat？
        # if peer.ip == "0.0.0.0" or peer.ip == self.station.ip:
        if peer.ip == "0.0.0.0":
            return False

        beat_dictdata = {"command": beat_cmd,
                         "parameters": {
                             "node": self.station.beat_info(),
                             "peer": peer.beat_info(),
                             "net_id": self.station.net_id,
                             "timestamp": int(time.time())
                         }}
        beat_msg = Beater.BeatMessage(dictdata=beat_dictdata)

        if now - peer.last_out > 10 or beat_cmd == "beat_res" or is_try:
            #                 logging.debug("beat_msg %s"%beat_msg.dict_data)
            self.station.send_appmsg_peer_id(beat_msg, peer.node_id, False, always=True)
            peer.last_out = int(now)
        if not peer.status and not is_try:
            if self.station.auto_path and self.station.pather:
                self.station.pather.request_path(peerid)

        return True

    def process(self, msg, addr):
        """
        #修改心跳者信息，若有更新的其他peer信息也同步修改
        #node is beat_src  peer is self
        """
        btmsg = Beater.BeatMessage(bindata=msg.get("app_data"))
        if btmsg is None:
            return
        #         logging.debug("%d receive btmsg %s from %s"%(self.station.node_id,btmsg.dict_data,"%s:%d"%addr))

        #         net_id = btmsg.get("parameters")["net_id"]
        #         if not self.station.net_id == PublicNetId and not net_id in (self.station.net_id,PublicNetId):
        #             logging.warning("%d receive not same net beat,discard %s"%(self.station.node_id,net_id))
        #             return

        distance = 7 - msg.get("ttl")
        command = btmsg.get_command()

        err_info = btmsg.get_parameter("error_info")
        if err_info:
            logging.warning("{0} encount beat error {1}".format(self.station.node_id, err_info))
            return

        # if command == "find_node":
        #     self.path_process(command, btmsg.get("parameters"))
        #     return

        if command in ("req_id",):
            node_id = self.set_peer_info(msg, addr)
            if node_id:
                logging.debug("{}: new peer node_id {}" .format (self.station.node_id, node_id))
                self.res_id(node_id, addr)

        if command in ("res_id",):
            self_info = btmsg.get_parameter("peer")
            if not self.station.node_id:
                self.station.node_id = self_info["node_id"]
                self.station.ip = self_info["ip"]
                self.station.port = self_info["node_port"]
                self.station.save_node_id()

        if command in ("beat_req", "beat_res"):
            peer_info = btmsg.get_parameter("peer")
            if peer_info and peer_info.get("node_id", None) == self.station.node_id:
                self.set_self_info(peer_info, addr, distance)
            #             self.set_peer_info(command,parameters["node"],parameters["timestamp"],addr,distance,parameters)
            self.set_peer_info(msg, addr)
        if command == "beat_req":
            node_info = btmsg.get_parameter("node")
            if node_info and "node_id" in node_info:
                self.send_beat(node_info["node_id"], beat_cmd="beat_res", is_try=True)
        return

    def beat_null(self):
        """
        keep nat firewall remain open port
        """
        self.station.underlayer.send(b"0",
                                     (socket.inet_ntoa(
                                         struct.pack('I', socket.htonl(random.randint(1677721600, 1694498816)))),
                                      random.randint(10000, 60000)))
        logging.debug("{0} beat null".format(self.station.node_id))

    def send_offline(self):
        beat_dictdata = {"command": "offline",
                         "parameters": {
                             "node": self.station.beat_info(),
                             "peer": self.station.beat_info()
                         }}
        beat_msg = Beater.BeatMessage(dictdata=beat_dictdata)
        self.station.send_appmsg_peer_id(beat_msg, BroadCastId, False, always=False)

    def _is_private_ip(self, ip):
        if ip.startswith("172.") or ip.startswith("192.") or ip.startswith("10."):
            return True
        else:
            return False

    def req_id(self):
        self.station.node_id = b'\0'*6
        for peer_id in self.station.peers:
            self.send_beat(peer_id, beat_cmd="req_id", is_try=True)
        return

    def res_id(self, node_id, addr):
        beat_dictdata = {"command": "res_id",
                         "parameters": {
                             "node": self.station.beat_info(),
                             "peer": self.station.peers[node_id].beat_info(),
                             "net_id": self.station.net_id,
                             "timestamp": int(time.time())
                         }}
        beat_msg = Beater.BeatMessage(dictdata=beat_dictdata)
        self._direct_send(addr, 0, beat_msg)
        self.station.delete_peer(node_id)

    def set_self_info(self, peer: dict, addr: tuple, distance: int = 1) -> None:
        if not peer["node_id"] == self.station.node_id \
                or peer["node_ip"] == "0.0.0.0" or self._is_private_ip(peer["node_ip"]):
            return
        if distance > 1:
            if self.station.nat_type == NAT_TYPE["Unknown"] and distance < self.station.distance:
                self.station.nat_type = peer["nat_type"]
                self.station.distance = distance
                logging.debug("set self nattype to %s from undirect peer info" % NAT_STRING[self.station.nat_type])
            return
        if not self.station.status:
            self.station.ip = peer["node_ip"]
            self.station.port = peer["node_port"]
            nat_type = peer["nat_type"]
            if not nat_type == NAT_TYPE["Unknown"]:
                self.station.nat_type = nat_type
                self.station.distance = 1
            logging.info(
                "set self {0} nattype to {1} from peer!".format(self.station.node_id,
                                                                NAT_STRING[self.station.nat_type]))
            self.station.status = True
            # start_new_thread(self.station.publish, ())
            self.station.last_beat_addr = addr
            logging.info("{0} connect to the world.".format(self.station.node_id))
        else:
            if self.station.ip == peer["node_ip"] and self.station.port == peer["node_port"]:
                if not self.station.last_beat_addr == addr:
                    self.station.nat_type = NAT_TYPE["Turnable"]
                    self.station.distance = 1
                    logging.debug(
                        "{0}: set {0} nattype to {1} for differen direct connect".format(self.station.node_id,
                                                                                         NAT_STRING[
                                                                                             self.station.nat_type]))
                    self.station.last_beat_addr = addr
            else:
                if self.station.ip == "0.0.0.0":
                    self.station.ip = peer["node_ip"]
                    self.station.port = peer["node_port"]
                    self.station.nat_type = peer["nat_type"]
                    logging.info("set self {0} info to {1} from peer!".format(self.station.node_id,
                                                                              NAT_STRING[self.station.nat_type]))
                else:
                    self.station.nat_type = NAT_TYPE["Unturnable"]
                    self.station.distance = 1
                    logging.debug(
                        "set self {0} nattype to {1} for not same ip port".format(self.station.node_id,
                                                                                  NAT_STRING[
                                                                                      self.station.nat_type]))

    #     def set_peer_info(self,command,node_info,timestamp,addr,distance,parameters=None):
    def set_peer_info(self, ppmsg, addr):
        btmsg = Beater.BeatMessage(bindata=ppmsg.get("app_data"))
        distance = 7 - ppmsg.get("ttl")
        command = btmsg.get("command")
        parameters = btmsg.get("parameters")
        node_info = parameters["node"]
        node_id = node_info["node_id"]

        if node_id == b'\0'*6:
            if command == "req_id" and distance == 1:
                # node_id = self.station.get_free_id()
                node_id = packaddr(addr)
                node_info["node_id"] = node_id
                logging.debug("{}: set peer node_id {}" .format (self.station.node_id, node_id))
            else:
                return 0
        if node_id not in self.station.peers:
            self.station.peers[node_id] = PPNode(node_id=node_id)

        peer = self.station.peers[node_id]
        peer.delay = (int(time.time() - parameters["timestamp"]) + peer.delay) / 2
        if parameters:
            peer.net_id = parameters["net_id"]

        if command == "offline":
            peer.status = False
            peer.distance = 10
            logging.info("{} is offline." .format( node_id))
            return 0

        # wrong id
        if peer.status and not self._is_private_ip(peer.ip) \
                and node_info["node_ip"] == "0.0.0.0":
            parameters1 = {"error_info": "duplication node_id,maybe some one use the id.",
                           "net_id": self.station.net_id}

            btmsg = Beater.BeatMessage(dictdata={"command": "beat_res",
                                                 "parameters": parameters1})
            self._direct_send(addr=addr, dst_id=node_info["node_id"], btmsg=btmsg)

            return 0

        if peer.distance < distance and peer.status:
            return 0

        if not peer.status:
            logging.info("{0}: {1} is online.".format(self.station.node_id, node_id))

        peer.load_dict({"status": True, "beat_interval": 1})

        # 部分nat 连接会更改端口
        if distance == 1:
            peer.load_dict(node_info)
            peer.load_dict({"node_ip": addr[0], "node_port": addr[1], "distance": distance, "turn_server": 0})
            if node_info["node_ip"] == "0.0.0.0":
                self.send_beat(node_id, beat_cmd="beat_res", is_try=True)
        else:
            if distance < peer.distance:
                turn_id = self.station.get_node_by_addr(addr)
                peer.load_dict({"node_ip": addr[0], "node_port": addr[1], "distance": distance, "turn_server": turn_id})

            if node_info["nat_type"] in (NAT_TYPE["Turnable"], NAT_TYPE["Unknown"]) \
                    and node_info["node_ip"] not in (peer.ip, "0.0.0.0", self.station.ip) \
                    and command == "beat_res":
                old_node_info = peer.dump_dict()
                peer.load_dict(node_info)
                peer.load_dict({"nat_type": NAT_TYPE["Turnable"]})
                logging.info("peer turnable try to direct connect to : %d,%s,%d,%s" % (
                    peer.node_id, peer.ip, peer.port, NAT_STRING[peer.nat_type]))
                self.send_beat(node_id, "beat_req", is_try=True)
                peer.load_dict(old_node_info)
                peer.load_dict({"nat_type": NAT_TYPE["Unturnable"]})

            if self.station.nat_type in (NAT_TYPE["Turnable"], NAT_TYPE["Unknown"]) \
                    and node_info["node_ip"] not in (peer.ip, "0.0.0.0", self.station.ip) \
                    and command == "beat_res":
                old_node_info = peer.dump_dict()
                peer.load_dict(node_info)
                logging.info("self turnable try to direct connect to : %d,%s,%d,%s" % (
                    peer.node_id, peer.ip, peer.port, NAT_STRING[peer.nat_type]))
                self.send_beat(node_id, "beat_req", is_try=True)
                peer.load_dict(old_node_info)

            if peer.nat_type == NAT_TYPE["Unknown"]:
                peer.nat_type = node_info["nat_type"]
        return node_id
