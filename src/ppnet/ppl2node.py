# coding=utf-8
'''
Created on 2018年2月28日

@author: heguofeng

pplink
todo:
用dh 交换，加密

'''
import logging
import struct
import threading
import time
import traceback
import yaml
from _thread import start_new_thread

from ppnet.common import get_app_name, restart_nic, of_bytes
from ppnet.config import PP_APPID, BroadCastId, NAT_STRING, NAT_TYPE
from ppnet.ppl1node import PPLayer, PPL1Node


class TLV(object):
    def __init__(self, tag=None, length=0, value=None):
        self.tag = tag
        self.length = length
        self.value = value

    def load(self, bindata):
        try:
            self.tag, self.length = struct.unpack("BH", bindata[:4])
            self.value = struct.unpack("%ds" % self.length, bindata[4:4 + self.length])[0]
            return self
        except:
            logging.debug("error when decode tlv %s" % bindata[:8])
            return None

    def bin_length(self):
        return self.length + 4

    def dump(self):
        """
        (tag,length,value)  value is bytes
        """
        if 0 == self.length:
            self.length = len(self.value)
        try:
            bindata = struct.pack("BH%ds" % self.length,
                                  self.tag, self.length, self.value)
            return bindata
        except:
            logging.debug("error when encode tlv {0} {1} {2}".format(self.tag, self.length, self.value))
            return None


class PPMessage(object):
    """
    Frame：

    src_ip src_port  dst_ip dst_port   sequence  needack+ttl  reserve  app_id  appdatalen   appdata
    4byte  2Byte     4byte  2byte      2byte     1b+000+4bit   1Byte    2byte   2byte        appdatalen

    appid:     app        appdata

    >>>pm=PPMessage(dictdata={"ttl":5})
    >>>bindata = pm.dump()
    >>>pm2 = PPMessage(bindata=bindata)
    >>>pm2.get("ttl")
    5

    """

    def __init__(self, **kwargs):
        self.dict_data = {"src_id": b"", "dst_id": b"", "sequence": 0, "ttl": 6, "need_ack": False,
                          "reserve": 0, "app_id": 0, "app_data": b""}
        if "dictdata" in kwargs:
            self.dict_data.update(kwargs["dictdata"])
        elif "bindata" in kwargs:
            self.load(kwargs["bindata"])
        else:
            self.dict_data.update(kwargs)
        # if "sequence" not in self.dict_data:
        #     self.dict_data["sequence"] = 0
        # if "ttl" not in self.dict_data:
        #     self.dict_data["ttl"] = 6
        # if "need_ack" not in self.dict_data:
        #     self.dict_data["need_ack"] = False
        pass

    def get(self, kw):
        return self.dict_data.get(kw, None)

    def set(self, kw, value):
        self.dict_data[kw] = value
        return

    def length(self):
        return 20 + len(self.dict_data["app_data"])

    def load(self, bindata):
        try:
            result = struct.unpack("6s6sHBBHH", bindata[:20])

            self.dict_data["src_id"] = result[0]
            self.dict_data["dst_id"] = result[1]
            # self.dict_data["src_port"] = result[2]
            # self.dict_data["dst_port"] = result[3]
            self.dict_data["sequence"] = result[2]
            self.dict_data["ttl"] = result[3] & 0x7
            self.dict_data["need_ack"] = True if result[3] & 0x80 else False
            self.dict_data["app_id"] = result[5]
            app_data_len = result[6]
            self.bin_length = 20 + app_data_len
            self.dict_data["app_data"] = struct.unpack("%ds" % app_data_len, bindata[20:20 + app_data_len])[0]
        except Exception as exp:
            logging.debug("error when decode ppmessage (%d)%s \n%s" % (len(bindata), bindata[:20], exp))
        return self

    def dump(self):
        #         print(self.dict_data,self.dict_data["ttl"]|(0x80 if self.dict_data["need_ack"] else 0))
        app_data_len = len(self.dict_data["app_data"])
        try:
            return struct.pack("6s6sHBBHH%ds" % app_data_len,
                               self.dict_data.get("src_id", b"0"),
                               self.dict_data.get("dst_id", b"0"),
                               # self.dict_data["src_port"],self.dict_data["dst_port"],
                               self.dict_data.get("sequence", 0) & 0xffff,
                               self.dict_data.get("ttl", 6) | (0x80 if self.dict_data.get("need_ack", False) else 0),
                               0,
                               self.dict_data.get("app_id", PP_APPID["Raw"]),
                               app_data_len,
                               self.dict_data["app_data"],
                               )
        except struct.error as exp:
            logging.debug("error in struct.pack: {} \n{}".format(exp, self.dict_data))

        return b""


class PPApp(object):
    '''
    PPApp is a model for layer service,need overload
    1。AppMessage
    2、method
    每个App需要4个方法
    set_underlayer_process(send_func,receive_func)
    send(data,addr)  for upperlayer send data
    receive(timeout)  for upperlayer receive data return data,addr
    process(msg,addr) for underlayer callback

    ppapp = PPApp(callback)
    node.addservice(ppapp)

    callback will happen define by yourself
    you can set timer do check

    note:
       tagid = 0  is reserver for session,
    '''

    class AppMessage(object):
        """
        as a base class of app , can use {tagstring:value} mode
        appid
        tags_id = {"filename":1}
        tags_string = {1:"filename"}
        parameters_type={1:"str","start":"H"}  # str,H B I
        dictdata or bindata

        appdata:
        appcmd   app_parameter_lens
        1byte      1byte

        parameters:
            tag     length  value
            1byte   2bytes  nbytes

        every element in tags_id will encode in bin ,else will not encoded in bin
        every element in bin must in tags_string, else will discard the message

        """

        def __init__(self, app_id, tags_id={}, tags_string={}, parameter_type={}, **kwargs):
            self.app_id = app_id
            self.tags_id = tags_id.copy()
            if tags_string:
                self.tags_string = tags_string.copy()
            if not tags_string:
                self.tags_string = self.id2string(self.tags_id)
            self.parameter_type = parameter_type

            self.dict_data = {}
            self.bin_length = 0
            if "dictdata" in kwargs:
                self.dict_data = kwargs["dictdata"].copy()
            elif "bindata" in kwargs:
                self.load(kwargs["bindata"])
            else:
                self.dict_data = kwargs

        def load(self, bindata):
            try:
                command, _ = struct.unpack("BB", bindata[0:2])
                data_parameters = {}
                start_pos = 2
                while start_pos < len(bindata):
                    tlv = TLV().load(bindata[start_pos:])
                    if not tlv:
                        return None
                    data_parameters[tlv.tag] = tlv.value
                    start_pos += tlv.bin_length()
                self.data2dict(data_parameters)

                if command in self.tags_string:
                    self.dict_data["command"] = self.tags_string[command]
                parameters = self.dict_data["parameters"].copy()
                self.dict_data["parameters"] = {}  # comment  to comptable
                for para in parameters:
                    if para in self.tags_string:
                        self.dict_data["parameters"][self.tags_string[para]] = parameters[para]
            except Exception as exp:
                print(self.dict_data)
                logging.warning(
                    "error when decode {0} app_message {1}\n {2}".format(get_app_name(self.app_id), bindata, exp))
                return None
            return self

        def dump(self):
            command = self.tags_id[self.dict_data["command"]]
            parameters = self.dict_data["parameters"].copy()
            temp_dictdata = {"parameters": {}}
            for para in parameters:
                if para in self.tags_id:
                    temp_dictdata["parameters"][self.tags_id[para]] = parameters[para]

            data = struct.pack("BB",
                               command, len(self.dict_data["parameters"])
                               )
            data_parameters = self.dict2data(temp_dictdata)
            for tag in data_parameters:
                tlv = TLV(tag=tag, length=len(data_parameters[tag]), value=data_parameters[tag])
                data += tlv.dump()
            return data

        def dict2data(self, dict_data):
            data_parameters = {}
            for para in dict_data["parameters"]:
                if para in self.parameter_type.keys():
                    if self.parameter_type[para] == "str":
                        data_parameters[para] = dict_data["parameters"][para].encode()
                    elif self.parameter_type[para] in ("I", "H", "B"):
                        data_parameters[para] = struct.pack(self.parameter_type[para], dict_data["parameters"][para])
                    else:
                        data_parameters[para] = dict_data["parameters"][para]
                else:
                    data_parameters[para] = dict_data["parameters"][para]
            return data_parameters

        def data2dict(self, data_parameters):
            self.dict_data["parameters"] = {}
            for para in data_parameters:
                if para in self.parameter_type:
                    if self.parameter_type[para] == "str":
                        self.dict_data["parameters"][para] = data_parameters[para].decode()
                    elif self.parameter_type[para] in ("I", "H", "B"):
                        self.dict_data["parameters"][para] = \
                            struct.unpack(self.parameter_type[para], data_parameters[para])[0]
                    else:
                        self.dict_data["parameters"][para] = data_parameters[para]
                else:
                    self.dict_data["parameters"][para] = data_parameters[para]
            return

        def get(self, item):
            return self.dict_data.get(item, None)

        def get_parameter(self, parameter):
            if "parameters" in self.dict_data:
                return self.dict_data["parameters"].get(parameter, None)
            else:
                return None

        def get_command(self):
            return self.dict_data.get("command", None)

        def get_app_id(self):
            return self.app_id

        def id2string(self, id_dict):
            string_dict = {}
            for name in id_dict.keys():
                string_dict[id_dict[name]] = name
            return string_dict

    def __init__(self, app_id, station=None, callback=None):
        self.app_id = app_id
        self.station = station
        self.set_callback(callback)
        self.timer = None
        self.quitting = False

    def start(self):
        '''
        must need overload,to load service_process
        '''
        logging.info("{} {} is start." .format (self.station.node_id, get_app_name(self.app_id)))
        return self

    def quit(self):
        if self.timer:
            self.timer.cancel()
        pass

    def get_app_id(self):
        return self.app_id

    def set_station(self, station):
        self.station = station

    def process(self, ppmsg, src):
        '''
        一般下层会直接调用本方法，经过适当处理，再调用上层的方法
        :param msg: PPMessage
        :param addr:
        :return: None
        '''
        if ppmsg.get("app_id") == self.app_id:
            app_msg = self.AppMessage(app_id=ppmsg.get("app_id"), bindata=ppmsg.get("app_data"))

            if self.callback:
                self.callback(app_msg, src)
            else:
                logging.warning("no callback define for appid = %d" % self.app_id)
        else:
            logging.warning("message is not for appid = %d" % self.app_id)
        pass

    def send_app_message(self, app_msg_dict, dst):
        '''

        :param app_msg_dict:
        :param dst: dst_id
        :return:
        '''
        app_msg = self.AppMessage(self.app_id, dictdata=app_msg_dict)
        return self.station.send(PPMessage(app_id=self.app_id, app_data=app_msg.dump()), dst)

    def receive_app_message(self, timeout):
        if self.station:
            ppmsg = self.station.receive(timeout)
            if ppmsg:
                if ppmsg.get("app_id") == self.app_id:
                    app_msg = self.AppMessage(ppmsg.get("app_id"), ppmsg.get("bindata"))
                    return app_msg.dict_data
                else:
                    logging.warning("message is not for appid = %d" % self.app_id)
        logging.warning("No station for appid = %d" % self.app_id)

    def set_callback(self, callback):
        self.callback = callback
        return self

    def support_commands(self):
        return ["info", "help"]

    def run_command(self, command_string):
        cmd = command_string.split(" ")
        if cmd[0] == "info":
            return "app_id %d \n" % self.app_id
        if cmd[0] == "help":
            return "you can use: %s" % (" ".join(self.support_commands()))
        return ""


class PPNetApp(PPApp):
    '''
    subclass should have self.process
    '''

    def __init__(self, app_id, station, callback=None):
        super().__init__(app_id, station, callback)
        self.waiting_list = {}  # simple for app in one packet
        self.session_list = {}  # for multi packet process
        self.session_id = 0

    def send_msg(self, peer_id, app_msg, need_ack=False, always=False):
        if peer_id == self.station.node_id:
            logging.warning("send msg to self.")
            return 0
        if always and not self.station.get_status(peer_id):
            do_wait(lambda: self.station.path_requester.request_path(peer_id),
                    lambda: self.station.get_status(peer_id),
                    3)
        return self.station.send_msg(peer_id, app_msg, need_ack, always)

    def waiting_reply(self, peer_id, app_msg):
        '''
        send with block and return msg
        '''
        app_id = app_msg.get("app_id")
        self.waiting_list[(peer_id, app_id)] = None
        self.send_msg(peer_id, app_msg, need_ack=True)
        loopcount = 0
        while loopcount < 500 and not self.waiting_list[(peer_id, app_id)]:
            time.sleep(0.1)
            loopcount += 1
        return self.waiting_list[(peer_id, app_id)]

    def session(self, peer_id, session_id, app_msg, size=0):
        '''
        session without block
        '''
        if session_id == 0:
            self.session_id += 1
        real_session_id = session_id if not session_id == 0 else self.session_id
        session = {"id": real_session_id, "size": size}
        app_msg.set_session(session)
        #         logging.debug(app_msg.dict_data)
        self.send_msg(peer_id, app_msg, need_ack=False)
        return real_session_id

    def waiting_session(self, peer_id, app_msg, parameter, size):
        """
        session block and return data of given parameter
        """
        session_id = self.session(peer_id=peer_id, session_id=0, app_msg=app_msg, size=size)
        self.session_list[(peer_id, session_id)] = Block(block_id=parameter)
        self.send_msg(peer_id, app_msg, need_ack=False)

        loopcount = 0
        while loopcount < 500 and not self.session_list[(peer_id, session_id)].complete:
            time.sleep(0.1)
            loopcount += 1
        return self.session_list[(peer_id, session_id)].buffer

    def process(self, msg, addr):
        '''
        need overload
        '''
        app_msg = self.AppMessage(app_id=msg.get("app_id"), bindata=msg.get("app_data"))
        #         app_msg = self.AppMessage(app_id = msg.get("app_id"),dictdata = msg.dict_data)
        logging.debug(app_msg.dict_data)
        session = app_msg.get_session()
        peer_id = app_msg.get("src_id")
        app_id = app_msg.get("app_id")
        if session:
            if (peer_id, session["id"]) in self.session_list:
                block = self.session_list[(peer_id, session["id"])]
                if "size" in session:
                    block.setInfo(size=session["size"], md5=session["md5"])
                if "start" in session:
                    block.add(session["start"], session["end"], app_msg.get_parameter(block.block_id))
                pass
        if (peer_id, app_id) in self.waiting_list:
            self.waiting_list[(peer_id, app_id)] = app_msg.get("app_data")
        print(msg.dict_data, addr)
        pass


class PPNode(object):
    '''
    .节点信息  主要用于peer
    '''

    def __init__(self, **kwargs):
        self.node_id = b"\0" * 6

        self.ip = "0.0.0.0"
        self.port = 0
        self.local_addr = ("0.0.0.0", 0)
        self.external_addr = ("0.0.0.0", 0)
        self.nat_type = NAT_TYPE['Unknown']

        self.will_to_turn = True
        self.secret = ""

        self.last_in = int(time.time())
        self.last_out = int(time.time()) - 200
        self.status = False  # True = alive
        self.turn_server = 0  # 针对非turn节点，其转接点        return self
        self.distance = 10
        self.last_beat_addr = (0, 0)

        # 心跳间隔，若多次没有回复，则可以扩大心跳间隔。在station中设置beat计数器，只有是beat_interval的倍数时，发送beat信息
        self.beat_interval = 1
        self.byte_in = 0
        self.byte_out = 0
        self.packet_in = 0
        self.packet_out = 0
        self.byte_turn = 0
        self.packet_turn = 0

        self.delay = 1000

        # 必须得到确认包的 sequence 序列。
        # 应用中的序列保证 通过应用自身进行 ，建议用sequence 链接
        self.tx_sequence = int(time.time()) & 0x00ffff
        self.rx_queue = [0, ] * 20

        self.last_ack = 0
        self.tx_window = 5
        self.tx_buffer = {}
        self.tx_retry = 0
        #        self.tx_queue = []   #list of tx_id
        self.tx_queue = {}  # dict {sequence: (bin_msg,retry_count)}
        self.rx_sequence = 0
        self.auto_path = False
        self.path = []

        if "node_dict" in kwargs:
            self.load_dict(kwargs["node_dict"])
        else:
            self.load_dict(kwargs)

    def check_turnable(self):
        if self.will_to_turn and is_turnable(self.nat_type):
            return self.status
        return False

    def __str__(self):
        return "node: %d addr:%s %s (d=%d t=%d) %s " % (self.node_id,
                                                        "%s:%d" % (self.ip, self.port),
                                                        NAT_STRING[self.nat_type], self.distance, self.turn_server,
                                                        "online" if self.status else "offline")

    def set_node_id(self, node_id):
        self.node_id = node_id

    def set_path(self, path):
        '''

        :param path: [(node_id,ip,port,nat)...]
        :return:
        '''
        self.path = list(map(lambda x: x[0], path))
        return self.path

    def set_status(self, status):
        if status == self.status:
            return
        logging.info("%s is %s!" % (self.node_id, "offline" if not status else "online"))
        self.status = status
        if not status:
            self.distance = 10

    def set_flow_status(self, receive_count=0, send_count=0, ppmsg: PPMessage = None):
        self.byte_out += send_count
        self.packet_out += 1
        self.last_out = int(time.time())
        if ppmsg and ppmsg.get("need_ack"):
            self.tx_queue.update({ppmsg.get("sequence"): (ppmsg, 1)})
        return

    def dump_dict(self, detail=False):
        node_dict = {"node_id": self.node_id, "node_ip": self.ip, "node_port": self.port,
                     "nat_type": self.nat_type, "will_to_turn": self.will_to_turn,
                     "secret": self.secret, }

        if detail:
            node_dict.update({"status": self.status, "last_out": self.last_out,
                              "last_in": self.last_in, "turn_server": self.turn_server,
                              "beat_interval": self.beat_interval, "distance": self.distance,
                              "tx_queue": self.tx_queue, "delay": self.delay})
        return node_dict

    def beat_info(self):
        node_info = self.dump_dict(detail=False)
        if not self.status:
            node_info["nat_type"] = NAT_TYPE["Unknown"]
        return node_info

    def _load_addr(self, nodedict):
        ip, port = "0.0.0.0", 0
        if "node_ip" in nodedict:
            ip = nodedict["node_ip"]
        if "node_port" in nodedict:
            try:
                port = int(nodedict["node_port"])
            except:
                port = 0
        return (ip, port)

    def load_dict(self, nodedict):
        if "node_id" in nodedict:
            self.node_id = of_bytes(nodedict["node_id"])
        if "node_ip" in nodedict:
            self.ip, _ = self._load_addr(nodedict)
        if "node_port" in nodedict:
            _, self.port = self._load_addr(nodedict)
        if "local_addr" in nodedict:
            self.local_addr = self._load_addr(nodedict["local_addr"])
        if "external_addr" in nodedict:
            self.external_addr = self._load_addr(nodedict["external_addr"])
        if "nat_type" in nodedict:
            self.nat_type = int(nodedict["nat_type"])
        if "will_to_turn" in nodedict:
            self.will_to_turn = nodedict["will_to_turn"]
        if "secret" in nodedict:
            self.secret = nodedict["secret"]
        if "last_in" in nodedict:
            self.last_in = nodedict["last_in"]
        if "last_out" in nodedict:
            self.last_out = nodedict["last_out"]
        if "status" in nodedict:
            self.status = nodedict["status"]
        if "turn_server" in nodedict:
            self.turn_server = nodedict["turn_server"]
        if "beat_interval" in nodedict:
            self.beat_interval = nodedict["beat_interval"]
        if "distance" in nodedict:
            self.distance = int(nodedict["distance"])
        if "status" in nodedict:
            self.status = nodedict["status"]
        if "path" in nodedict:
            self.path = list(map(lambda x: of_bytes(x), nodedict["path"]))
        if "auto_path" in nodedict:
            self.auto_path = nodedict["auto_path"]
        return self

    def save_node_id(self):
        if "test_mode" in self.config:
            return
        cf = open("node.id", "w")
        yaml.dump({"node_id": self.node_id}, cf)
        return

    def load_node_id(self):
        if "test_mode" in self.config:
            return 0
        try:
            config = yaml.load(open("node.id"))
            if "node_id" in config:
                return config["node_id"]
        except:
            return 0


class PPL2Node(PPLayer, PPNode):
    '''
    单个节点，完成自动应答

    config_dict = {
                    "node_id":100,
                    "node_port":54320,
                    "node_secret":"password",
                    "nodes": [(id,ip,port,type)..] or  "nodes_db":nodes.pkl

                    "net_secret":"password"}

    linker = PPLinker(config = config_dict，msg_callback=None,ack_callback=None)
    linker.start()

    linker.send_msg(peer,pp_msg,need_ack=False)
        if receive will call msg_callback
        if need_ack and ack_callback ,will call ack_callback
        ...

    linker.quit()

    linklayer:  PPMessage,PPApp,PPApp.AppMessage,PPNode,PPLinker,PPAcker,FakeNet,NAT

    '''

    def __init__(self, config={}, msg_callback=None, ack_callback=None):
        if config:
            self.config = config
            PPNode.__init__(self, node_id=config.get("node_id", b"0"),
                            node_ip=config.get("node_ip", "0.0.0.0"),
                            node_port=config.get("node_port", 7071),
                            nat_type=config.get("nat_type", 5),
                            will_to_turn=config.get("will_to_turn", True),
                            secret=config.get("node_secret", ""))
            PPLayer.__init__(self)
        else:
            raise ("Not correct config!")
        self.message_callback = msg_callback
        self.set_underlayer(PPL1Node((self.ip, self.port)))
        self.add_service(Ackor(self, callback=ack_callback))
        self.lock = threading.RLock()
        pass

    def start(self):
        '''
        ack_callback(dst_id,sequence,ack_status)
        '''
        self._underlayer.start()

        self.quitting = False

        logging.info("%s Layer2 is runing!" % (self.node_id,))
        for service in self.services:
            self.services[service].start()

        self.not_runing = 0
        start_new_thread(self.check_runing, ())
        start_new_thread(self.wait_receive, ())

        return self

    def quit(self):
        logging.info("{0} Layer2 is quitting...".format(self.node_id))
        self.quitting = True
        for service in self.services:
            self.services[service].quit()
            logging.info("{0} {1} is quit.".format(self.node_id, get_app_name(service)))

        time.sleep(1)
        self.underlayer.quit()

    def check_runing(self):
        if self.not_runing > 3:
            self.restart_network_interface()
            self.not_runing = 0
        if not self.quitting:
            self.timer = threading.Timer(60, self.check_runing)
            self.timer.start()

    def restart_network_interface(self, nic):
        self.not_runing = 0
        if "node_nic" in self.config:
            nic = self.config["node_nic"].encode("gbk").decode()
            print(nic)
            restart_nic(nic)
        pass

    def wait_receive(self):
        logging.debug("{0} start receive {1}".format(self.node_id, self.rx_queue))
        while not self.quitting:
            try:
                ppmsg, addr = self.receive()
                if ppmsg:
                    self.process_msg(ppmsg, addr)
            except Exception as e:
                logging.debug(traceback.format_exc())
                logging.warning(repr(e))

    def receive(self, count=1522):
        data, addr = self._underlayer.receive()
        if data and addr:
            return PPMessage(bindata=data), addr
        return None, None

    def send(self, ppmsg, addr, need_ack=False):
        if ppmsg.get("src_id") == b"":
            ppmsg.set("src_id", self.node_id)
        if ppmsg.get("sequence") == 0:
            self.lock.acquire()
            self.tx_sequence += 1
            ppmsg.set("sequence", self.tx_sequence)
            self.lock.release()
        ppmsg.set("need_ack", need_ack)
        bin_msg = ppmsg.dump()
        logging.debug("{0}: send {1} to {2}".format(self.node_id, bin_msg[:16], addr))
        self.underlayer.send(bin_msg, addr)
        self.byte_out += ppmsg.length()
        self.packet_out += 1
        pass

    def send_ppmsg_peer(self, ppmsg, peer, need_ack=False):
        """
        peer 是一个对象
        return sequence    0 if failure
        if need_ack must have ack,will retry 3 times if no_ack, then call ack_callback(sequence,False)

        """
        addr = (peer.ip, peer.port)
        self.send(ppmsg, addr, need_ack)
        sequence = ppmsg.get("sequence")
        # if need_ack:
        #     peer.tx_queue.update({sequence: (ppmsg, 1)})
        peer.set_flow_status(send_count=ppmsg.length())

        logging.debug("{0}: send {1}(seq={2})(ttl={3}) to {4}:({5},{6}).".format(self.node_id,
                                                                                 get_app_name(ppmsg.get("app_id")),
                                                                                 sequence, ppmsg.get("ttl"),
                                                                                 peer.node_id, (peer.ip, peer.port),
                                                                                 NAT_STRING[peer.nat_type]))
        return sequence

    def process_msg(self, ppmsg: object, addr: object) -> None:
        dst_id = ppmsg.get("dst_id")
        if dst_id == self.node_id or dst_id == BroadCastId:
            sequence = ppmsg.get("sequence")
            src_id = ppmsg.get("src_id")
            # 回响应包
            if ppmsg.get("need_ack") and not dst_id == BroadCastId:
                self.services[PP_APPID["Ack"]].send_ack({"src_id": src_id, "sequence": sequence}, addr)

            if (src_id, sequence) in self.rx_queue:
                logging.debug("{0} duplication message! {1}".format(self.node_id, self.rx_queue))
                return
            else:
                self.rx_queue.append((src_id, sequence))
                self.rx_queue.pop(0)
                self.byte_in += ppmsg.length()
                self.packet_in += 1

            app_id = ppmsg.get("app_id")
            if app_id in self.services:
                self.services[app_id].process(ppmsg, addr)
                return

        ''' call upper layer process'''
        if self.message_callback:
            self.message_callback(ppmsg, addr)
        else:
            logging.warning("{0} no process seting for {1}".format(self.node_id, get_app_name(ppmsg.get("app_id"))))

    def process_bindata(self, data, addr):
        try:
            ppmsg = PPMessage(bindata=data)
            logging.debug("%d receive %s (seq=%d)(ttl=%d) from %s to %s addr %s!" % (self.node_id,
                                                                                     get_app_name(ppmsg.get("app_id")),
                                                                                     ppmsg.get("sequence"),
                                                                                     ppmsg.get("ttl"),
                                                                                     ppmsg.get("src_id"),
                                                                                     ppmsg.get("dst_id"), addr))
            self.process_msg(ppmsg, addr)
        except Exception as exp:
            logging.warning("can't decode %s from (%s,%d) Error %s " % (data, addr[0], addr[1], exp))
        return

    def support_commands(self):
        return ["quit"]

    def run_command(self, command_string):
        cmd = command_string.split(" ")
        run_message = ""
        if cmd[0] == "quit":
            self.quitting = True
            run_message = "node quitted!\n"
        return run_message + super().run_command(command_string)


class Ackor(PPApp):
    '''
    callback(peer_id,sequence,status)
    '''

    class AckMessage(PPMessage):
        """
        appid   applen  appdata
        ack     4       sequence
        """

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.dict_data["app_id"] = PP_APPID["Ack"]

        def load(self, bindata):
            try:
                result = struct.unpack("I", bindata)
                self.dict_data["sequence"] = result[0]
            except:
                logging.debug("error when decode AckMessage %s" % bindata)
            return

        def dump(self):
            data = struct.pack("I",
                               self.dict_data["sequence"],
                               )
            return data

    def __init__(self, station, callback=None):
        super().__init__(PP_APPID["Ack"], station, callback)

    def process(self, msg, addr):
        """
        # 处理确认包
        call ack_callback,由上层自行决定是否处理
        """
        ackmsg = Ackor.AckMessage(bindata=msg.get("app_data"))
        src_id = msg.get("src_id")
        sequence = ackmsg.get("sequence")

        if self.callback:
            self.callback({"src_id": src_id, "sequence": sequence}, addr, True)
        else:
            # drop
            pass

    def send_ack(self, data, addr):
        dictdata = {
            "dst_id": data["src_id"],
            "app_data": Ackor.AckMessage(dictdata={"sequence": data["sequence"]}).dump(),
            "app_id": PP_APPID["Ack"]}
        self.station.send(PPMessage(dictdata=dictdata), addr)
