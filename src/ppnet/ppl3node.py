# coding=utf-8 
'''
Created on 2018年2月28日

@author: heguofeng

todo:
用dh 交换，加密

'''
import json
import logging
import requests
import socket
import struct
import time
from queue import Queue

from ppnet.common import set_debug, do_wait, of_bytes
from ppnet.config import BroadCastId, NAT_TYPE, PP_APPID
from ppnet.config import PublicNetId
from ppnet.ppbeater import Beater
from ppnet.ppl2node import PPApp, PPL2Node, PPNode, PPNetApp, PPMessage


class PathRequester(PPNetApp):
    '''
    pr =  PathRequester(station)
    pr.request_path(node_id)
    '''

    class PathReqMessage(PPApp.AppMessage):
        '''

            appid    appdata
            0002     cmd,tlv(node_id),tlv(pathlimit),tlv(pathlen),tlv(nodes)
                     nodes = [(id0,ip0,port0,nattype0,)id1...ids ]

        command = "path_req":1,"path_res":2,"node_set":3,
        parameters =  "node_id":4,"path_limit":5,"path_len":6,"path":7
        path = [(id0,ip0,port0,nattype0),(id1...),...(ids...)]
        '''

        def __init__(self, **kwargs):
            app_id = PP_APPID["PathReq"]
            tags_id = {"path_req": 1, "path_res": 2, "node_set": 3,
                       "node_id": 4, "path_limit": 5, "path_len": 6, "bin_path": 7}
            tags_string = {1: "path_req", 2: "path_res", 3: "node_set",
                           4: "node_id", 5: "path_limit", 6: "path_len", 7: "bin_path"}
            parameter_type = {4: "s", 5: "B", 6: "B", 7: "s"}
            super().__init__(app_id, tags_id, tags_string, parameter_type, **kwargs)

        def load_path(self, bin_path, path_len):
            path = []
            for i in range(0, path_len):
                noderesult = struct.unpack("6sIHB", bin_path[i * 15:i * 15 + 15])
                path.append((noderesult[0],
                             socket.inet_ntoa(struct.pack('I', socket.htonl(noderesult[1]))),
                             noderesult[2],
                             noderesult[3]))
            return path

        def dump_path(self, path):
            data = b""
            for i in range(0, len(path)):
                node = path[i]
                nodedata = struct.pack("6sIHB", node[0],
                                       socket.ntohl(struct.unpack("I", socket.inet_aton(node[1]))[0]),
                                       node[2], node[3])
                data += nodedata
            return data

        def load(self, bindata):
            if None == super().load(bindata):
                return None
            #             super().load(bindata)
            #             self.dict_data["parameters"]["nodes"] = self.load_path(self.dict_data["parameters"]["bin_path"],
            #                                                                   self.dict_data["parameters"]["path_len"])

            # result = struct.unpack("6sBB", bindata[:8])
            # self.dict_data = {"parameters": {}}
            # self.dict_data["parameters"]["node_id"] = result[0]
            # self.dict_data["parameters"]["path_limit"] = result[1]
            # self.dict_data["parameters"]["path_len"] = result[2]
            if "bin_path" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["nodes"] = self.load_path(self.dict_data["parameters"]["bin_path"],
                                                                       self.dict_data["parameters"]["path_len"])
                del self.dict_data["parameters"]["bin_path"]
            # self.dict_data["parameters"]["nodes"] = self.load_path(bindata[8:],
            #                                                        self.dict_data["parameters"]["path_len"])

            return self

        def dump(self):
            self.dict_data["parameters"]["bin_path"] = self.dump_path(self.dict_data["parameters"]["nodes"])
            #             return super().dump()

            # binlen = len(self.dict_data["parameters"]["bin_path"])
            # # data = struct.pack("6sBB%ds" % binlen,
            # #                    self.dict_data["parameters"]["node_id"],
            # #                    self.dict_data["parameters"]["path_limit"],
            # #                    self.dict_data["parameters"]["path_len"],
            # #                    self.dict_data["parameters"]["bin_path"]
            # #                    )
            return super().dump()

    def __init__(self, station):
        super().__init__(PP_APPID["PathReq"], station)
        pass

    def request_path(self, req_id, path_limit=5, dest_id=BroadCastId):
        if self.station.status:
            return self.send_pathreq(dest_id, req_id, path_limit, "path_req", [
                (self.station.node_id, self.station.ip, self.station.port, self.station.nat_type)])
        return False

    def send_pathreq(self, destid, req_node_id, path_limit=3, command="path_req", path: list = []):
        prmsg = self.PathReqMessage(dictdata={"command": command,
                                              "parameters": {
                                                  "node_id": req_node_id,
                                                  "path_limit": path_limit,
                                                  "path_len": len(path),
                                                  "nodes": path
                                              }})
        self.station.send_appmsg_peer_id(prmsg, destid)
        return True

    def find_in_path(self, node_id, path):
        for i in range(len(path)):
            if path[i][0] == node_id:
                return i
        return -1

    def process(self, ppmsg, addr):
        prmsg = PathRequester.PathReqMessage(bindata=ppmsg.get("app_data"))
        command = prmsg.get_command()
        parameters = prmsg.get("parameters")
        path_limit = prmsg.get_parameter("path_limit")
        path = parameters["nodes"]
        req_node_id = parameters["node_id"]
        logging.debug("{1} : receive pathreq for {2} path:{0}".format(path, self.station.node_id, req_node_id))
        # self.station.set_nodes(path)

        if command in ["path_req"]:
            if self.find_in_path(self.station.node_id, path) > -1:
                return
            path.append((self.station.node_id, self.station.ip, self.station.port, self.station.nat_type))
            if req_node_id in (self.station.node_id):
                self.station.set_nodes(path)
                for node in path:
                    self.send_pathreq(node[0], req_node_id, path_limit, "path_res", path)
            else:
                if len(path) > path_limit:  # exceed path_limit
                    return
                else:
                    self.send_pathreq(BroadCastId, req_node_id, path_limit, "path_req", path)
        if command in ["path_res"]:
            path.append((self.station.node_id, self.station.ip, self.station.port, self.station.nat_type))
            if path[0][0] == self.station.node_id:
                self.station.set_nodes(path)
                req_postion = self.find_in_path(req_node_id, path)
                current_path = self.station.set_node_path(req_node_id, path[1:req_postion + 1])
                if len(current_path) == req_postion:  # 本次的有效
                    if len(path) < 2 * req_postion + 1:  # return path is short than forward path
                        for i in range(req_postion, len(path)):
                            self.send_pathreq(path[i][0], self.station.node_id, path_limit, "path_res",
                                              path[req_postion:])
                            self.request_path(req_node_id, path_limit, dest_id=path[i][0])
            else:
                postion = self.find_in_path(self.station.node_id, path)
                for index in range(postion - 1, -1, -1):
                    self.send_pathreq(path[index][0], req_node_id, path_limit, "path_res", path)


class Dataer(PPNetApp):
    '''
    dataer =  Dataer(station,callback)
    dataer.send_text(node_id,data,echo,callback)

    callback(node_id,text)
    '''

    class DataMessage(PPMessage):
        '''
        parameters = {
                "data":"test",}
        tm = DataMessage(dictdata={"command":"send",
                                   "parameters":parameters} )
        bindata = tm.dump()
        tm1 = DataMessage(bindata=bindata)
        app_id = tm1.get("app_id")
        data = tm1.get("parameters")["data"]

        src_id   dst_id   app_id  sequence applen  appdata
        4byte    4byte    2byte   4byte   2byte   applen

        appid:     app        appdata
        000f       data       [cmd,paralen,tag,len,value,tag len value ...]
                                1    1     TLV
        cmd(parameters):
            send(data)    1
        parameters(type,struct_type):
            data        bytes     s
        '''

        def __init__(self, data):
            super().__init__(app_id=PP_APPID["Data"],
                             app_data=data)

    def __init__(self, station, callback=None):
        super().__init__(PP_APPID["Data"], station, callback)
        self.queue = Queue()

    pass

    def send_data(self, data, addr, callback=None):
        peer_id = self.station.get_node_by_addr(addr)
        if peer_id:
            if self.station.find_path(peer_id):
                data_msg = self.DataMessage(data)
                data_msg.set("dst_id", peer_id)
                self.station.send(data_msg)
            else:
                logging.warning("peer not online, try later")
        else:
            logging.warning("unkown address {0}".format(addr))
        pass

    def receive_data(self, timeout=5):
        try:
            item = self.queue.get(block=True, timeout=timeout)
            if item:
                return item[0]
        except:
            # logging.debug("{2} receive:{0} from {1}".format(data,addr,self.node_id))
            # recv_time = item[1]
            # if time.time()-recv_time > 20:
            #     print("drop packet for timeout.")
            return (None, None)

    def process(self, ppmsg, addr):
        data = ppmsg.get("app_data")
        node_id = ppmsg.get("src_id")
        addr = self.station.get_node_addr(node_id)
        logging.debug("{2}: receive data from {0} :\n {1}".format(addr,
                                                                  ''.join('{:02x} '.format(x) for x in data[:16]),
                                                                  self.station.node_id))
        if self.callback:
            self.callback(data, addr)
        else:
            self.queue.put(((data, addr), int(time.time())))


class PPDhcp(PPNetApp):
    '''
    动态获得自己的ID，发布自己的ID
    '''

    def __init__(self, station, server=""):
        self.server = server

    def publish(self):
        pass

    def get_id(self):
        return b"123456"

    def get_free_id(self, check=False):
        max_id = max(self.peers.keys())
        '''
        check is it available 
        '''
        logging.debug(max_id)
        if not check:
            return max_id + 1
        self.station.pather.request_path(max_id, 6)
        time.sleep(2)
        if max_id not in self.peers:
            return max_id + 1
        return self.get_free_id()

    def get_addr(self, port):
        temp_config = self.config.copy()
        temp_config.update({"node_port": port, "node_id": 0, "test_mode": True, })
        temp_station = PPStation(config=temp_config)
        #         temp_station.node_id = 0
        temp_station.start()
        try_count = 0
        while not temp_station.node_id and try_count < 10:
            temp_station.beater.req_id()
            time.sleep(1)
            try_count += 1
        temp_station.quit()
        if temp_station.node_id:
            return temp_station.local_addr, (temp_station.ip, temp_station.port)
        return None, None

    def publish(self):
        # send self info to web directory
        if self.testing:
            return
        if self.nat_type == NAT_TYPE["Turnable"]:  # ChangedAddressError:  #must
            payload = {"ip": self.ip, "port": self.port, "node_id": self.node_id, "net_id": self.net_id}
            res = requests.post("http://ppnetwork.pythonanywhere.com/ppnet/public", params=payload)
            print(res.text)
        pass

    def get_peers_online(self):
        payload = {"net_id": self.net_id}
        response = requests.get("http://ppnetwork.pythonanywhere.com/ppnet/public", params=payload)
        peers = json.loads(response.text)
        peernodes = {}
        for peer in peers:
            if not int(peer) == self.node_id and peers[peer][0] and peers[peer][1]:
                peernodes[int(peer)] = PPNode(node_id=peer, ip=peers[peer][0], port=peers[peer][1])
        return peernodes


class Peers(object):
    def __init__(self):
        self.peers = {}

    def get_node_by_addr(self, addr):
        for peer_id in self.peers:
            if (self.peers[peer_id].ip, self.peers[peer_id].port) == addr:  # and self.peers[peer_id].distance == 1:
                return peer_id
        return 0

    def get_node_addr(self, peer_id):
        if peer_id in self.peers:
            return (self.peers[peer_id].ip, self.peers[peer_id].port)
        return None

    def get_node_send_addr(self, peer_id):
        if peer_id in self.peers:
            if self.peers[peer_id].path:
                return self.get_node_addr(self.peers[peer_id].path[0])
            else:
                return self.get_node_addr(peer_id)
        else:
            logging.debug("peer not in self peers.\n{}".format(self.peers))

    def set_node_addr(self, peer_id, addr):
        if peer_id not in self.peers:
            self.peers[peer_id] = PPNode(node_id=peer_id)
        self.peers[peer_id].ip = addr[0]
        self.peers[peer_id].port = addr[1]
        self.peers[peer_id].nat_type = NAT_TYPE["Unturnable"]
        return self.peers[peer_id]

    def set_node_path(self, peer_id, path):
        '''

        :param node_id:
        :param path: [(node_id,ip,port,nat)...]   1,2,3,4,5,6,4,1
        :return:
        '''
        if peer_id not in self.peers:
            self.peers[peer_id] = PPNode(node_id=peer_id)
        orglen = len(self.peers[peer_id].path)
        if orglen == 0 or orglen > len(path):
            return self.peers[peer_id].set_path(path)
        else:  # no change
            return self.peers[peer_id].path

        pass

    def get_node_path(self, peer_id):
        if peer_id in self.peers:
            return self.peers[peer_id].path
        return None

    def get_status(self, node_id):
        if node_id in self.peers:
            return self.peers[node_id].status
        else:
            logging.warning("Can't found {0} in peers.".format(node_id))
            return False

    def set_node_status(self, node_id, status):
        if node_id in self.peers and not status == self.peers[node_id].status:
            self.peers[node_id].set_status(status)
            for nid in self.peers:
                if self.peers[nid].turn_server == node_id:
                    self.set_status(nid, status)

    def set_node_flow_status(self, node_id, receive_count=0):
        if node_id in self.peers:
            node = self.peers[node_id]
            node.last_in = int(time.time())
            node.byte_in += receive_count
            node.packet_in += 1
            node.beat_interval = 1
            node.status = True

    def set_nodes(self, nodes):
        '''

        :param nodes: [(node_id,ip,port,nat_type)]
        :return:
        '''
        for node in nodes:
            self.set_node_addr(node[0], (node[1], node[2]))
        return

    def get_all_nodes(self, delay=2):
        print("Self Info:\n%s\nPeers Info:" % self)
        for peerid in self.peers:
            print(self.peers[peerid])

        return self.peers

    def delete_peer(self, peer_id):
        if peer_id in self.peers:
            self.peers.pop(peer_id)

    def dump_nodes(self):
        #        pickle.dump( self.peers, open( self.db_file, "wb" ) )
        with open(self.db_file, "w") as f:
            #             print(self.json_nodes())
            f.write(json.dumps(self._dump_nodes_to_dict()))
        pass

    def json_nodes(self, detail=False):
        nodes_dict = {}
        for peer in self.peers:
            nodes_dict["%d" % peer] = self.peers[peer].dump_dict(detail)
        #         nodes_dict[self.node_id] = self.dump_dict(detail)

        return json.dumps(nodes_dict)

    def _dump_nodes_to_dict(self, detail=False):
        nodes_dict = {}
        for peer_id in self.peers.keys():
            nodes_dict[peer_id.decode()] = self.peers[peer_id].dump_dict(detail)
        return nodes_dict

    def load_nodes(self, config):
        self.peers = {}

        if "node_file" in config:
            self.db_file = config["node_file"]
        else:
            self.db_file = "nodes.pkl"
        self._load_nodes_from_file(self.db_file)

        if "nodes" in config:
            self._load_nodes_from_dict(config["nodes"])
        if not self.peers:
            logging.warning("no peers now.")
            # todo
            # self.peers = self.get_peers_online()

    def _load_nodes_from_dict(self, nodes_dict):
        logging.debug(nodes_dict)
        for node in nodes_dict:
            bnode = of_bytes(node)
            self.peers[bnode] = PPNode().load_dict(nodes_dict[node])
            self.peers[bnode].beat_interval = 1

    def _load_nodes_from_file(self, filename):
        try:
            with open(filename, "rt") as f:
                nodes = json.loads(f.read())
                self._load_nodes_from_dict(nodes)
        except IOError:
            logging.warning("can't load nodes from %s" % filename)


class PPL3Node(PPL2Node, Peers):
    '''
    public 公布自己的信息，其他节点可以查询到自己状态
    will_to_turn 作为中转节点，如果自身是internet，fullcone，则其他节点可能通过该节点转发
    db_file 保存节点信息

       config_dict = {
                    "node_id":100,
                    "node_port":54320,
                    "node_secret":"password",
                    "nodes": [(id,ip,port,type)..] or  "nodes_db":nodes.pkl

                    "net_secret":"password"}
    '''

    def __init__(self, config={}):
        if config:
            super().__init__(config=config, msg_callback=self.process_msg_step2, ack_callback=self.ack_callback)
            #             self.db_file = self.config.get("db_file","nodes.pkl")
            if not self.node_id:
                self.node_id = self.load_node_id()
            self.net_id = config.get("net_id", 0xffffffff)
        else:
            raise ("Not correct config!")
        Peers.__init__(self)

        self.load_nodes(self.config)

        self.quitting = False
        self.beater = Beater(self)
        self.pather = PathRequester(self)
        self.add_service(self.beater)
        self.add_service(self.pather)
        self.dataer = Dataer(self)
        self.add_service(self.dataer)
        # self.netmanage = NetManage(self)

        pass

    def start(self):
        super().start()
        if not self.node_id:
            do_wait(self.beater.req_id, lambda: self.node_id, 3)
        logging.info("Station {0} is runing!".format(self.node_id))
        return self

    def quit(self):
        logging.info("Station is quitting...")
        if self.status:
            self.beater.send_offline()
        # self.dump_nodes()
        super().quit()

    def set_ipport(self, peer_id, ip, port):
        self.set_node_addr(peer_id, (ip, port))
        self.set_node_status(peer_id, True)
        self.beater.send_beat(peer_id, beat_cmd="beat_req", is_try=True)

    def find_path(self, peer_id):
        if self.get_status(peer_id):
            return True
        self.pather.request_path(peer_id)
        return False

    def set_route(self, peer_id, turn_id):
        if peer_id not in self.peers:
            self.peers[peer_id] = PPNode(node_id=peer_id)
        if turn_id in self.peers and peer_id in self.peers:
            self.peers[peer_id].turn_server = turn_id
            self.set_ipport(peer_id, self.peers[turn_id].ip, self.peers[turn_id].port)

    def _check_status(self):
        for peerid in self.peers:
            if self.peers[peerid].status:
                return True
                break
        return False

    def broadcast(self, ppmsg):
        for peer_id in self.peers:
            self.send(ppmsg, self.get_node_addr(peer_id))
        return

    def send(self, ppmsg, addr=None, need_ack=False):
        dst = ppmsg.get("dst_id")
        if not dst:
            logging.warning("no dst found! discard message:\n %s" % ppmsg)
            return 0
        if not addr:
            addr = self.get_node_send_addr(dst)
        return super().send(ppmsg, addr, need_ack)

    def send_appmsg_peer_id(self, app_msg, peer_id, need_ack=False, always=False):
        '''
        return sequence    0 if failure
        if need_ack must have ack,will retry 3 times if no_ack, then call ack_callback(sequence,False)
        ack_call back can be set by self.ack_callback = func  func(sequence,ackstatus) True have ack False else

        '''
        # 如果指定发送对象，则发给指定对象，如果未指定，则发送给节点中的所有 可连接节点
        # 检查是否在peers中，如果不在，
        if peer_id == BroadCastId:  # broadcast
            for tmp_peerid in self.peers:
                if self.peers[tmp_peerid].status:  # check_turnable():
                    self.send_appmsg_peer_id(app_msg, tmp_peerid, False, always)
            return
        else:  # unicast
            if peer_id == self.node_id:
                return 0
            if peer_id in self.peers:
                peer = self.peers[peer_id]
                app_data = app_msg.dump()
                ppmsg = PPMessage(dictdata={"net_id": self.net_id, "src_id": self.node_id, "dst_id": peer.node_id,
                                            "app_data": app_data, "app_len": len(app_data),
                                            "app_id": app_msg.get_app_id()})
                return self.send_ppmsg_peer(ppmsg, peer, need_ack=need_ack)

            logging.warning("{0} can't communicate to {1}".format(self.node_id, peer_id))
            return 0

    def forward_ppmsg(self, ppmsg, peer_id):
        '''
        forward to peer or broadcase ,    ttl 减一

        '''
        ttl = ppmsg.get("ttl")
        if ttl == 0:
            return
        if peer_id == BroadCastId:  # broadcast
            for peerid in self.peers:
                if self.peers[peerid].status:  # check_turnable():
                    ppmsg.set("ttl", ttl)
                    self.forward_ppmsg(peerid, ppmsg)
        else:  # unicast
            if peer_id == self.node_id:
                return 0
            if peer_id in self.peers:
                peer = self.peers[peer_id]
                ppmsg.set("ttl", ttl - 1)
                self.byte_turn += ppmsg.length()
                self.packet_turn += 1
                logging.debug("{0} forward to {1} ".format(self.node_id, peer_id))
                return self.send_ppmsg_peer(ppmsg, peer)

            logging.warning("{} can't communicate to {}".format(self.node_id, peer_id))
            return 0

    def process_msg_step2(self, ppmsg, addr):
        dst_id = ppmsg.get("dst_id")
        if dst_id in [self.node_id, BroadCastId]:
            src_id = ppmsg.get("src_id")
            app_id = ppmsg.get("app_id")
            self.set_node_flow_status(src_id, ppmsg.length())

            if dst_id == BroadCastId and app_id not in self.service:  # unknown app,just forward to peers ,try forward to dst_id
                self.forward_ppmsg(ppmsg, dst_id)
        else:
            self.forward_ppmsg(ppmsg, dst_id)

    def wait_status(self, node_id, timeout=5):
        count = 0
        while not self.get_status(node_id):
            time.sleep(1)
            count += 1
            if count > timeout:
                break
        return self.get_status(node_id)

    def support_commands(self):
        return ["beat", "find", "p2p", "cast", "route", "ipport", "help", "quit", "stat", "set", "control"]

    def run_command(self, command_string):
        cmd = command_string.split(" ")
        #
        if cmd[0] == "beat" and len(cmd) >= 2:
            node_id = int(cmd[1])
            self.beater.send_beat(node_id, "beat_req", is_try=True)
            if self.wait_status(node_id, timeout=3):
                self.texter.send_text(node_id, str(node_id) + " is online!", echo=True)
            else:
                print("%d is offline!" % (node_id))
        elif cmd[0] == "find" and len(cmd) >= 2:
            node_id = int(cmd[1])
            self.path_requester.request_path(node_id)
            time.sleep(2)
            if node_id in self.peers:
                print(self.peers[node_id])
            else:
                print("can't find path to %d" % node_id)
        elif cmd[0] == "p2p" and len(cmd) >= 3:
            self.texter.send_text(int(cmd[1]), command_string[5 + len(cmd[1]):])
        elif cmd[0] == "cast":
            self.texter.send_text(0xffffffff, command_string[5:])
        elif cmd[0] == "route" and len(cmd) >= 3:
            self.set_route(peer_id=int(cmd[1]), turn_id=int(cmd[2]))
        elif cmd[0] == "ipport" and len(cmd) >= 4:
            self.set_ipport(peer_id=int(cmd[1]), ip=cmd[2], port=int(cmd[3]))
        elif cmd[0] == "set" and len(cmd) >= 3 and cmd[1] == "nattype":
            self.nat_type = int(cmd[2])
        elif cmd[0] == "control" and len(cmd) >= 2 and cmd[1] == "publish":
            self.publish()
        elif cmd[0] == "stat":
            if len(cmd) == 2:
                peer_id = int(cmd[1])
                if peer_id == self.node_id:
                    print(self.dump_dict(detail=True))
                else:
                    print(self.peers[peer_id].dump_dict(detail=True))
            else:
                self.get_all_nodes(delay=0)
                print("Services:", self.services.keys())
        elif cmd[0] == "help":
            response = requests.get("http://ppnetwork.pythonanywhere.com/ppnet/help.txt")
            print(response.text.encode(response.encoding).decode())
        elif cmd[0] == "quit":
            self.quit()
        else:
            return False
        return True

    def ack_callback(self, peer_id, sequence, status):
        '''
        delete (peer_id,sequence) in tx_queue
        :param peer_id:
        :param sequence:
        :param status:
        :return:
        '''
        if peer_id in self.peers:
            self.peers[peer_id].tx_queue.pop(sequence, None)
        pass


def main(config):
    print("PPNetwork is lanching...")
    station = PPL3Node(config=config)
    station.start()
    try_count = 0
    while not station.status:
        time.sleep(2)
        station.status = station._check_status()
        try_count += 1
        if try_count > 10 or station.quitting:
            break
    print("node_id=%d online=%s" % (station.node_id, station.status))

    #     if station.status:
    #         station.path_requester.request_path(BroadCastId, 6)
    node_type = config.get("node_type", "server")
    is_client = node_type == "client"
    while not is_client and not station.quitting:
        time.sleep(3)

    s = "help"
    while not station.quitting:
        try:
            station.run_command(s)
            print("\n%d>" % station.node_id, end="")
        except Exception as exp:
            print(exp.__str__())
        if not station.quitting:
            s = input()

    print("PPNetwork Quit!")


if __name__ == '__main__':
    config = {"auth_mode": "secret", "secret": "password",
              "share_folder": ".", "net_id": PublicNetId,
              "pp_net": "home", "node_id": b"100",
              "node_port": 54320, "DebugLevel": logging.DEBUG,
              "nodes": {b"101": {"node_id": b"101", "ip": "127.0.0.1", "port": 54321, "nat_type": 0}}
              # (id,ip,port,type)..]
              }
    # config = yaml.load(open("fmconfig.yaml"))
    set_debug(config.get("DebugLevel", logging.WARNING),
              config.get("DebugFile", ""))

    main(config=config)

    pass
