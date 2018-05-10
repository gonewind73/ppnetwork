# coding=utf-8
'''
Created on 2018年2月28日

@author: heguofeng

pplink
todo:
用dh 交换，加密

'''
import unittest
import time
import socket

import threading
import struct

from _thread import start_new_thread

import logging
import random
import subprocess
import requests
import os
import sys

def set_debug(debug_level=logging.INFO, filename="", debug_filter=lambda record:True):
    console = logging.StreamHandler()
    console_filter = logging.Filter()
    console_filter.filter = debug_filter
    console.addFilter(console_filter)
    if filename:
        logging.basicConfig(level=debug_level,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename=filename,
                filemode='w',
                )
    else:
        logging.basicConfig(level=debug_level,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                handlers = [console,]
                )



BroadCastId = 0xffffffff
NAT_TYPE = {"Unknown":7, "Turnable":2, "Unturnable":5}
NAT_STRING = {2:"Turnable", 7:"Unknown", 5:"Unturnable"}

def is_turnable(nat_type):
    return nat_type < 3

class PPNode(object):
    '''
    .节点信息

    '''
    def __init__(self, **kwargs):
        self.node_id = 0
        self.net_id = 0
        self.net_secret = ""

        self.local_addr = ("0.0.0.0",0)
        self.external_addr = ("0.0.0.0",0)
        self.nat_type = NAT_TYPE['Unknown']

        self.will_to_turn = True
        self.secret = ""
        
        self.last_in = int(time.time())
        self.last_out = int(time.time()) - 200
        self.status = False  #  True = alive
        self.turn_server = ""  # 针对非turn节点，其转接点        return self
        self.distance = 10
        self.last_beat_addr = (0,0)

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
        self.tx_sequence = 0
        self.rx_queue = [0,]*20

        self.last_ack = 0
        self.tx_window = 5
        self.tx_buffer = {}
        self.tx_retry = 0
#        self.tx_queue = []   #list of tx_id
        self.tx_queue = {}  # dict of (tx_id:retrycount)
        self.rx_sequence = 0


        if "node_dict" in kwargs:
            self.load_dict(kwargs["node_dict"])
        else:
            self.load_dict(kwargs)

    def check_turnable(self):
        if self.will_to_turn and is_turnable(self.nat_type):
            return self.status
        return False

    def __str__(self):
        net_id = self.net_id if "net_id" in self.__dir__() else ""
        return "node: %d.%d addr:%s %s (d=%d) %s " % (net_id,self.node_id,
                                                         "%s:%d"%self.external_addr,
                                                         NAT_STRING[self.nat_type], self.distance,
                                                         "online" if self.status else "offline")

    def set_status(self,status):
        if status == self.status:
            return 
        logging.info("%s is %s!" % (self.node_id,"offline" if not status else "online"))            
        self.status = status
        if not status:
            self.distance = 10

    def dump_dict(self, detail=False):
        node_dict = {"node_id":self.node_id, "ip":self.ip, "port":self.port,
                    "nat_type":self.nat_type, "will_to_turn":self.will_to_turn,
                    "secret":self.secret,"net_id":self.net_id }

        if detail:
            node_dict.update({"status":self.status, "last_out":self.last_out,
                              "last_in":self.last_in, "turn_server":self.turn_server,
                              "beat_interval":self.beat_interval, "distance":self.distance,
                              "tx_queue":self.tx_queue,"delay":self.delay})
        return node_dict

    def beat_info(self):
        node_info = self.dump_dict(detail=False)
        if not self.status:
            node_info["nat_type"] = NAT_TYPE["Unknown"]
        return node_info

    def load_dict(self, nodedict):
        if "node_id" in nodedict:
            self.node_id = int(nodedict["node_id"])
        if "net_id" in nodedict:
            self.net_id = int(nodedict["net_id"])
        if "local_addr" in nodedict:
            self.local_addr = nodedict["local_addr"]
        if "external_addr" in nodedict:
            self.external_addr = nodedict["external_addr"]
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
            self.beat_interval = int(nodedict["beat_interval"])
        if "distance" in nodedict:
            self.distance = int(nodedict["distance"])
        return self
    
    def getToken(self,sequence):
        return b""*4
    
    def authenticate(self,ppmsg):
        '''
        to do and  authencation
        '''
        
        return True

PP_APPID = {
          "Auth":1,
         "Beat":7,
         "Ack":8,
         "PathReq":2,
         "PathRes":3,
         "Text":4,
         "FileCommand":20,
         "File":21,
         "Shell":22,
         "Storage":30,
         "NetManage":161,
         "Sock5":17,
         "Proxy":18,
         "Data":19,
         "VPN":15,
         }


class PPMessage(object):
    '''
    Frame：
    net_id        4Bytes
    net_token     4Bytes
    src_id   dst_id    sequence  needack+ttl    app_id  applen   appdata
    4byte    4byte   4byte        1b+000+4bit   2byte   2byte      applen

    appid:     app        appdata

    '''

    def __init__(self, **kwargs):
        self.dict_data = {}
        self.bin_length = 0
        if "dictdata" in kwargs:
            self.dict_data = kwargs["dictdata"].copy()
        elif "bindata" in kwargs:
            self.load(kwargs["bindata"])
        else:
            self.dict_data = kwargs
        if "sequence" not in self.dict_data:
            self.dict_data["sequence"] = 0
        if "ttl" not in self.dict_data:
            self.dict_data["ttl"] = 6
        pass

    def get(self, kw):
        return self.dict_data.get(kw, None)

    def set(self, kw, value):
        self.dict_data[kw] = value
        return

    def TLV(self, tag, length, value):
        return {"tag":tag, "length":length, "value":value}

    def load_TLV(self, bindata):
        try:
            tag, length = struct.unpack("BI", bindata[:8])
            value = struct.unpack("%ds" % length, bindata[8:8 + length])[0]
            return length + 8, (tag, length, value)
        except:
            logging.debug("error when decode tlv %s" % bindata[:8])
            return 0, (0, 0, b"")


    def dump_TLV(self, tlv):
        """
        (tag,length,value)  value is bytes
        """
        bindata = struct.pack("BI%ds" % tlv[1],
                            tlv[0], tlv[1], tlv[2])
        return bindata

    def load(self, bindata):
        try:
            result = struct.unpack("IIHIBH", bindata[:20])

            self.dict_data["src_id"] = result[0]
            self.dict_data["dst_id"] = result[1]
            self.dict_data["app_id"] = result[2]
            self.dict_data["sequence"] = result[3]
            self.dict_data["ttl"] = result[4]
            app_data_len = result[5]
            self.bin_length = 20+app_data_len
            self.dict_data["app_data"] = struct.unpack("%ds" % app_data_len, bindata[20:20+app_data_len])[0]
        except Exception as exp:
            logging.debug("error when decode ppmessage (%d)%s \n%s" %(len(bindata),bindata[:20],exp))
        return self

    def dump(self):

        app_data_len = len(self.dict_data["app_data"])
        data = struct.pack("IIHIBH%ds" % app_data_len,
                           self.dict_data["src_id"],
                           self.dict_data["dst_id"],
                           self.dict_data["app_id"],
                           self.dict_data["sequence"],
                           self.dict_data["ttl"],
                           app_data_len,
                           self.dict_data["app_data"],
                           )
        self.bin_length = 20+app_data_len
        return data

    @staticmethod
    def app_string(app_id):
        appid2name = {}
        for app_name in PP_APPID:
            appid2name[PP_APPID[app_name]] = app_name
        return appid2name.get(app_id, "Unknown")
    pass

    @staticmethod
    def unpackip(bin_ip):
        return socket.inet_ntoa(struct.pack('I', socket.htonl(struct.unpack("I",bin_ip)[0])))    
    @staticmethod 
    def packip(ip):
        return struct.pack("I",socket.ntohl(struct.unpack("I", socket.inet_aton(ip))[0]))     


class PPApp(object):
    '''
    PPApp is a model for upper layer,need overload
    1。AppMessage
    2、method

    ppapp = PPApp(station,callback)
    callback will happen define by yourself
    you can set timer do check

    note:
       tagid = 0  is reserver for session,
    '''
    class AppMessage(PPMessage):
        '''
        as a base class of app , can use {tagstring:value} mode
        appid
        tags_id = {"filename":1}
        tags_string = {1:"filename"}
        parameters_type={1:"str","start":"H"}  # str,H B I
        dictdata or bindata

        if you want compatable to appmessage,please add tags_id { 1:1,2:2...}

        src_id   dst_id   app_id  sequence applen  appdata
        4byte    4byte    2byte   4byte   2byte   applen

        appdata:
        appcmd   app_parameter_lens
        1byte      1byte

        parameters:
            tag     length  value
            1byte   2bytes  nbytes

        every element in tags_id will encode in bin ,else will not encoded in bin
        every element in bin must in tags_string, else will discard the message

        '''

        def __init__(self, app_id, tags_id={}, tags_string={}, parameter_type={}, **kwargs):
            self.tags_id, self.tags_string = tags_id, tags_string
            if not self.tags_string:
                self.tags_string = self.id2string(self.tags_id)
            if "session" in self.tags_id or 0 in self.tags_string:
                print(self.tags_id,self.tags_string)
                raise Exception("session and 0 is system tag ,can 't be define in app")
            self.tags_id.update({"session":0})
            self.tags_string.update({0:"session"})
            self.parameter_type = parameter_type
            super().__init__(**kwargs)
            self.dict_data["app_id"] = app_id

        def load(self, bindata):
            try:
                command, paralen = struct.unpack("BB", bindata[0:2])
                data_parameters = {}
                start_pos = 2
                while start_pos < len(bindata):
                    pos, result = self.load_TLV(bindata[start_pos:])
                    data_parameters[result[0]] = result[2]
                    start_pos += pos
                self.data2dict(data_parameters)

                if command in self.tags_string:
                    self.dict_data["command"] = self.tags_string[command]
                parameters = self.dict_data["parameters"].copy()
                self.dict_data["parameters"]={}   # comment  to comptable
                for para in parameters:
                    if para in self.tags_string:
                        self.dict_data["parameters"][self.tags_string[para]] = parameters[para]
            except Exception as exp:
                print(self.dict_data)
                logging.warning("error when decode %s app_message %s" % (
                    PPMessage.app_string(self.dict_data["app_id"]), bindata))
                logging.debug(exp)
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
                data += self.dump_TLV((tag, len(data_parameters[tag]), data_parameters[tag]))
            return data

        def dict2data(self,dict_data):
            data_parameters = {}
            for para in dict_data["parameters"]:
                if para in self.parameter_type:
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
                        self.dict_data["parameters"][para] = struct.unpack(self.parameter_type[para], data_parameters[para])[0]
                    else:
                        self.dict_data["parameters"][para] = data_parameters[para]
                else:
                    self.dict_data["parameters"][para] = data_parameters[para]
            return

        def set_session(self,session):
            '''
            session_info=session{id,size,start=0,end=-1)
            '''
            if "start" not in session:
                session["start"] = 0
            if "end" not in session or session["end"]==-1:
                session["end"]=session["size"]

            bin_session = struct.pack("IIII",session["id"],session["size"],session["start"],session["end"])
            self.dict_data["parameters"]["session"] = bin_session
            pass

        def get_session(self):
            bin_session = self.get_parameter("session")
            if not bin_session:
                return None
            session = struct.unpack("IIII",bin_session)
            return {"id":session[0],"size":session[1],"start":session[2],"end":session[3],"md5":b""}
            pass

        def get_parameter(self,parameter):
            if parameter in self.dict_data["parameters"]:
                return self.dict_data["parameters"][parameter]
            else:
                return None

        def id2string(self,id_dict):
            string_dict = {}
            for name in id_dict.keys():
                string_dict[id_dict[name]] = name
            return string_dict

    def __init__(self,station,app_id,callback=None):
        self.station = station
        self.app_id = app_id
        self.set_callback(callback)
        self.timer = None

    def start(self):
        '''
        must need overload,to load service_process
        '''
#         self.station.set_app_process(PP_APPID["File"], self.file_process)
        return self


    def quit(self):
        if self.timer:
            self.timer.cancel()
        pass

    def process(self,msg, addr):
        '''need overload'''
        print(msg,addr)
        pass

    def set_callback(self, callback=None):
        self.callback = callback
        return self

    def support_commands(self):
        return []

    def run_command(self,command_string):
        return False

class Receiver(PPApp):
    def __init__(self,station,callback):
        self.station = station
        self.callback = callback
        self.in_queue = [(0,0)]*10  #(peerid,sequence)
        self.not_runing = 0

    def start(self):
        start_new_thread(self.listen, ())
        return self

    def quit(self):
        pass

    def listen(self):
        while not self.station.quitting:
            self.receive_msg()
            self.not_runing = 0

    def _receive(self):
        return self.station._receive()

    def receive_msg(self):
        data, addr = self._receive()
        if not data:
            return
        try:
            ppmsg = PPMessage(bindata=data)
            logging.debug("%d receive %s (seq=%d)(ttl=%d) from %s to %s addr %s!" % (self.station.node_id,
                            PPMessage.app_string(ppmsg.get("app_id")), ppmsg.get("sequence"),ppmsg.get("ttl"),
                            ppmsg.get("src_id"), ppmsg.get("dst_id"), addr))
#             logging.debug(ppmsg.dict_data)
        except Exception as exp:
            logging.warning("can't decode %s from (%s,%d) Error %s " % (data, addr[0], addr[1], exp))
            return
        self.process_msg(ppmsg, addr)

    def process_msg(self, ppmsg, addr):

        net_id = ppmsg.get("net_id")
        if self.station.net_id:
            if net_id == self.station.net_id :
                if not self.station.authenticate(ppmsg):
                    return  #discard authenticate failue 

        dst_id = ppmsg.get("dst_id")            
        if dst_id == self.station.node_id or dst_id == BroadCastId:
            sequence = ppmsg.get("sequence")
            src_id = ppmsg.get("src_id")
            app_id = ppmsg.get("app_id")
            # 回响应包
            if  ppmsg.get("ttl") & 0x80 and not dst_id == BroadCastId:
                self.station.ackor.send_ack(src_id,sequence,addr)

            if (net_id,src_id,sequence) in self.in_queue:
                    logging.debug("duplication message! %s"%self.in_queue)
                    return
            else:
                self.in_queue.append((net_id,src_id,sequence))
                self.in_queue.pop(0)
                self.station.byte_in += len(ppmsg.get("app_data")) + 20
                self.station.packet_in += 1

            if ppmsg.get("app_id")==PP_APPID["Ack"]:
                self.station.ackor.process(ppmsg,addr)
                return

        ''' call upper layer process'''
        if self.callback:
            self.callback(ppmsg,addr)
        else:
            logging.warning("%s no process seting for %s"%(self.station.node_id,ppmsg.get("app_id")))


class Ackor(PPApp):
    '''
    callback(peer_id,sequence,status)
    '''
    class AckMessage(PPMessage):
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

    def __init__(self,station,callback=None):
        super().__init__(station,PP_APPID["Ack"],callback)

    def start(self):
        super().start()
        self.ack_queue = {}  #(dst_id,sequence):(addr,bin_msg,retry_count)
        start_new_thread(self.check_ack, ())
        self.not_runing = 0
        return self

    def quit(self):
        super().quit()

    def process(self, msg, addr):
        """
        # 处理确认包
        delete tx_queue[sequence]
        call ack_callback
        """
        ackmsg = Ackor.AckMessage(bindata=msg.get("app_data"))
        src_id = msg.get("src_id")
        sequence = ackmsg.get("sequence")
        if (src_id,sequence) in self.ack_queue:
            logging.debug("%d receive ack info %d sequence %d"%(self.station.node_id,src_id,sequence))
            del self.ack_queue[(src_id,sequence)]
            if self.callback:
                self.callback(src_id,sequence, True)
        else:
            # drop
            pass

    def add_ack_queue(self,peer_id,sequence,addr,bin_msg):
        self.ack_queue[(peer_id,sequence)]=(addr,bin_msg,0)

    def send_ack(self,peer_id,sequence,addr):
        self.station.tx_sequence += 1
        sequence1 = self.station.tx_sequence
        dictdata={"src_id":self.station.node_id,"dst_id":peer_id,
                  "app_data":Ackor.AckMessage(dictdata={"sequence":sequence}).dump(),
                  "app_id":PP_APPID["Ack"],"sequence":sequence1}

        pp_ack_msg = PPMessage(dictdata=dictdata)
        self.station._send(addr,pp_ack_msg.dump())

    def check_ack(self):
        for (peerid,sequence) in list(self.ack_queue.keys()):
            addr,bin_msg,retry_count = self.ack_queue[(peerid,sequence)]
            if retry_count > 3:
                del self.ack_queue[ (peerid,sequence)]
                if self.callback:
                    self.callback(peerid,sequence,False)
            else:
                self.station._send(addr, bin_msg)
                self.ack_queue[(peerid,sequence)] = (addr,bin_msg,retry_count+1)

        if not self.station.quitting:
            self.timer = threading.Timer(3, self.check_ack)
            self.timer.start()
            self.not_runing = 0


# class PPConnection(PPApp):
#
#     def __init__(self, station, callback=None):
#         '''
#         callback = (action,peer_id,action_content="",error_code=0,error_message="")
#         '''
#         super().__init__(station,callback)
#         self.peer_id = 0
#
#     def connect(self, peer_id):
#         '''
#         '''
#         if self.peer_id and not self.peer_id == peer_id:
#             return None
#         if not self.peer_id:
#             if self.callback:
#                 self.callback("connect", peer_id)
#         self.peer_id = peer_id
#
#         return self
#
#     def disconnect(self, peer_id):
#         '''
#         '''
#         self.peer_id = 0
#         if self.callback:
#             self.callback("diconnect", peer_id)
#         return self
#
#     def send(self, app_msg, need_ack=False):
#         if self.peer_id:
#             self.station.send_msg(self.peer_id, app_msg, need_ack)
#
#     def set_app_process(self, app_id, process=None):
#         self.station.set_app_process(app_id, process)
#     
#     def finish(self, action, peer_id, action_content, error_code, error_message):
#         print("%s with %d done return %d with %s " % (action, peer_id, error_code, error_message))


class PPLinker(PPNode):
    '''
    config_dict = { "node_id":100,
                    "node_port":54320,
                    "node_secret":"password",
                    "nodes": [(id,ip,port,type)..] or  "nodes_db":nodes.pkl
                    "net_id":"public",+
                    "net_secret":"password"}

    linker = PPLinker(config = config_dict)
    linker.start(msg_callback,ack_callback=None)

    linker.send_msg(peer,pp_msg,need_ack=False)
        if receive will call msg_callback
        if need_ack and ack_callback ,will call ack_callback
        ...

    linker.quit()

    linklayer:  PPMessage,PPApp,PPApp.AppMessage,PPNode,PPLinker,PPAcker,FakeNet,NAT

    '''

    def __init__(self, config={},ack_callback=None,net_callback=None):
        if config:
            self.config = config
            super().__init__(node_id=config["node_id"],
                             ip = config.get("node_ip", "0.0.0.0"),
                             port = config.get("node_port", 54320),
                             nat_type = config.get("nat_type",5),
                             will_to_turn=config.get("will_to_turn", True),
                             secret=config.get("node_secret", ""))
        else:
            raise("Not correct config!")

        self.neighbor = {}
        self.receiver = Receiver(self,callback = net_callback)
        self.ackor = Ackor(self,callback=ack_callback)
        self.services = {"receiver":self.receiver,"ackor":self.ackor}
        pass

    def start(self):
        '''
        ack_callback(dst_id,sequence,ack_status)
        '''
        if os.path.exists("start.bat"):
            subprocess.check_output("start.bat")
        if os.path.exists("reload.bat"):
            self.quitting = True
            subprocess.check_output("reload.bat")

        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logging.info("Socket bind to %s,%d" % (self.ip, self.port))
        try:
            self.sockfd.bind((self.ip, self.port))
        except:
            pass
        if self.ip=="0.0.0.0":
            self.nat_type = NAT_TYPE["Unknown"]
        self.quitting = False

        logging.info("Linker is runing!")
        for service in self.services:
            self.services[service].start()
            logging.info("%s is start."%service)

        self.not_runing = 0
        start_new_thread(self.check_runing, ())

        return self

    def quit(self):
        logging.info("Linker is quitting...")
        self.quitting = True
        self.receiver.quit()
        self.ackor.quit()
        time.sleep(1)
        self.sockfd.close()

        if os.path.exists("reload.bat"):
            subprocess.check_output("reload.bat" ,cwd = ".", shell=False)

    def check_runing(self):
        self.ackor.not_runing += 1
        self.receiver.not_runing += 1
        if  self.ackor.not_runing > 3:
            self.ackor.start()
        if  self.receiver.not_runing > 3:
            self.receiver.start()
            self.not_runing +=1
        if  self.not_runing >3:
            self.restart_network_interface()
            self.not_runing = 0
        if not self.quitting:
            self.timer = threading.Timer(60, self.check_runing)
            self.timer.start()


    def _is_private_ip(self, ip):
        if ip.startswith("172.") or ip.startswith("192.") or ip.startswith("10."):
            return True
        else:
            return False

    def restart_network_interface(self):
        self.not_runing = 0
        if "node_nic" in self.config:
            nic = self.config["node_nic"].encode("gbk").decode()
            print(nic)
            subprocess.getstatusoutput('netsh interface set interface "' + nic + '" disabled')
            time.sleep(10)
            subprocess.getstatusoutput('netsh interface set interface "' + nic + '" enabled')
        pass

    def publish(self):
        # send self info to web directory
        if  self.nat_type != NAT_TYPE["Unknown"]:  # ChangedAddressError:  #must
            payload = {"nat_type":self.nat_type, "ip":self.ip, "port":self.port, "net_id":self.net_id, "node_id":self.node_id}
            requests.post("http://joygame2.pythonanywhere.com/p2pnet/public", params=payload)
        pass

    def send_ppmsg(self, peer, ppmsg, need_ack=False):
        '''
        return sequence    0 if failure
        if need_ack must have ack,will retry 3 times if no_ack, then call ack_callback(sequence,False)

        '''
        if ppmsg.get("sequence") == 0:
            self.tx_sequence += 1
            sequence = self.tx_sequence
#            sequence = int(time.time()%100*10000000)
            ppmsg.set("sequence", sequence)
            ppmsg.set("token",self.getToken(sequence))

        sequence = ppmsg.get("sequence")
        addr = (peer.ip,peer.port)
        if need_ack:
            ppmsg.set("ttl", ppmsg.get("ttl") | 0x80)
            bin_msg = ppmsg.dump()
            self.ackor.add_ack_queue(peer.node_id,sequence,addr,bin_msg)
        else:
            bin_msg = ppmsg.dump()
        self._send(addr,bin_msg)

        peer.byte_out += len(ppmsg.get("app_data")) + 20
        peer.packet_out += 1
        peer.last_out = int(time.time())
        logging.debug("%d send %s(seq=%d)(ttl=%d) to %s on (%s,%s,%s)." % (self.node_id,
            PPMessage.app_string(ppmsg.get("app_id")), sequence, ppmsg.get("ttl"),
            peer.node_id, peer.ip, peer.port,NAT_STRING[peer.nat_type]))
        return sequence

    def _send(self, addr, data):
        try:
            self.sockfd.sendto(data, addr)
            self.byte_out += len(data)
            self.packet_out += 1
        except OSError as error:
            logging.debug("%s ip:%s port %d" % (error, addr[0], addr[1]))

    def _receive(self):
        try:
            data, addr = self.sockfd.recvfrom(1500)
            self.neighbor[addr] = 1

            self.byte_in += len(data)
            self.packet_in += 1
            self.not_runing = 0
            return data, addr
        except (socket.timeout, OSError) as exps:
            print(exps)
            return None, None

    def support_commands(self):
        return ["quit"]

    def run_command(self,command_string):
        cmd = command_string.split(" ")
        if cmd[0] not in self.support_commands():
            print("not support command!")
        else:
            if cmd[0] == "quit":
                self.quit()
            pass

def main(config):
    print("PPLinker is lanching...")
    station = PPLinker(config=config)
    station.start()

    s= "help"
    while not station.quitting:
        try:
            station.run_command(s)
            print("\n%d>"%station.node_id,end="")
        except Exception as exp:
            print(exp.__str__())
        if not station.quitting:
            s=input()

    station.quit()
    print("PPlink Quit!")

if __name__ == '__main__':
    config = { "node_id":100,
                    "node_port":54320,
                    "node_secret":"password",
                    "DebugLevel":logging.DEBUG,
                    "DebugFile":"",
                    }
#     config = yaml.load(open("fmconfig.yaml"))

    set_debug(config.get("DebugLevel", logging.WARNING),
              config.get("DebugFile", ""))
    main(config=config)

    pass


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
#         print(self.buffer)

    def receive(self, node_id=0, nat=None):
        '''
        self.stationA._receive = lambda : self.fake_net.receive(100)
        '''
#         time.sleep(1)

        dst_addrs = nat.inaddrs()
#         print(nat.ip,dst_addrs,)
        for dst_addr in list(dst_addrs.keys()):
#             print("buffer",dst_addr,self.buffer.keys(),dst_addr in self.buffer)

            if dst_addr in self.buffer and self.buffer[dst_addr]:
#                 print("enter receive")
#                 print("receive:", self.buffer[dst_addr][0][0])
                try:
                    data, addr = self.buffer[dst_addr].pop(0)[0]
                    if addr == dst_addrs[dst_addr] or dst_addrs[dst_addr] == dst_addr:

    #                 if not nat.in_(addr[0],addr[1]) ==(None,None):
                        return data, addr
                    else:
                        print("drop packet for can't in.")
                except Exception as exp:
                    print(exp)
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
        print(station.ip,station.port,station.nat_type)
        station._send = lambda addr,data: self.send(addr,data,nat)
        station._receive = lambda : self.receive(station.node_id,nat)
        return station


class Test(unittest.TestCase):
    inited = 0

    def start(self):
        self.fake_net = FakeNet()
        set_debug(logging.DEBUG, "")

        self.stationA = self.fake_net.fake(PPLinker(config={"node_id":100, "node_ip":"118.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]}))
        self.stationB = self.fake_net.fake(PPLinker(config={"node_id":201, "node_ip":"116.153.152.193", "node_port":54330, "nat_type":NAT_TYPE["Turnable"]}))
        self.stationC = self.fake_net.fake(PPLinker(config={"node_id":202, "node_ip":"116.153.152.193", "node_port":54320, "nat_type":NAT_TYPE["Turnable"]}))
        self.inited = 1

    def setUp(self):
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
        self.ackResult = False
        dictdataA={"src_id":100,"dst_id":201,
                    "app_data":b"app_data",
                    "app_id":7}
        self.stationA.start(msg_callback=None,ack_callback=self.ack_callback)
        self.stationB.start(msg_callback=None)
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
