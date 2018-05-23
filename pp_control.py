# coding=utf-8 
'''
Created on 2018年2月28日

@author: heguofeng

todo:
用dh 交换，加密

'''
import time
import json
import requests
import socket

import threading
import struct

from _thread import start_new_thread

import logging
import yaml
import random
from pp_link import  PPApp, PPLinker, PPNode, BroadCastId, NAT_TYPE,\
    NAT_STRING, PPMessage, PP_APPID, set_debug, PublicNetId, do_wait
import platform
import binascii
import hashlib


_BEAT_CMD = {"beat_req":1,
           "beat_res":2,
           "beat_set":3,
           "offline":4,
           "echo_req":5,
           "echo_res":6,
           }

class Block(object):
    def __init__(self, block_id="", buffer=b""):
        self.pos = 0
        self.size = 0
        self.mtime = int(time.time())
        self.load(block_id, buffer)
        pass
    
    def open(self, mode="rb"):
        self.pos = 0
        return self
    
    def close(self, mtime=0):
        if mtime:
            self.mtime = mtime
        return self
    
    def load(self, block_id, buffer):
        self.buffer = buffer
        self.size = len(self.buffer)
        if block_id:
            self.block_id = block_id
        else:
            self.block_id = binascii.b2a_hex(self.get_md5()).decode()
        self.pos = 0
        return self
    
    def load_file(self, file_name, mode="rb"):
        '''
        need override for sub class
        '''
        self.block_id = file_name
        with open(file_name, mode) as f:
            buffer = f.read()
        self.load(self.block_id,buffer)
        return self
    
    def load_buffer(self):
        '''
        for continue transfer  after failure
        return file_md5,file_size,received_bytes,unreceived blocks dictionay
        {start1:end1,...startn,endn}
        '''
        return "", 0, 0, {}
    
    def save_buffer(self, file_md5, file_size, received_bytes, buffer):
        '''
        for continue transfer  after failure
        return unreceived blocks dictionay
        {start1:end1,...startn,endn}
        '''
        return 
    
    def seek(self, start, mode=0):
        '''
        0 from begin
        '''
        self.pos = start if start < self.size else self.size
        
    def read(self, byte_count):
        end = self.pos + byte_count if self.pos + byte_count < self.size else self.size
        return self.buffer[self.pos:end]
    
    def write(self, bindata):
        front = self.pos if self.pos > self.size else self.size
        tail = self.pos + len(bindata)  if self.pos + len(bindata) < self.size else self.size
        self.buffer = self.buffer[:front] + bindata + self.buffer[tail:]
        self.size = len(self.buffer)
        self.pos = self.pos + len(bindata)
        
    def get_md5(self, start=0, end=0):
        md5obj = hashlib.md5()
        self.seek(start, 0)
        realend = end if end else self.size
        for _ in range(0, int((realend - start) / 1024)):
            buffer = self.read(1024)
            if not buffer:
                break
            md5obj.update(buffer)
        buffer = self.read((realend - start) % 1024)
        if buffer:
            md5obj.update(buffer)
        return md5obj.digest()
    
    def setInfo(self,size,md5=b""):
        self.size = size
        self.md5 = md5
        self.part_buffer = {}
        self.complete = False
        
    def addPart(self,start,end,data):
        if end not in self.part_buffer:
            self.part_buffer[start] =(end,data)
        else:
            buffer1 = self.part_buffer[end]
            self.part_buffer[start]=(buffer1[0],data+buffer1[1])
            del self.part_buffer[end]
        if self.part_buffer[0][0] == self.size:
            self.buffer = self.part_buffer[0][1]
            self.complete = True
            
    def isComplete(self):
        return self.complete and self.md5 == self.get_md5()
    
    def getPartRemain(self):
        
        remains = {}
        save_list = sorted(self.part_buffer.keys())
        start = 0
        for i in range(len(save_list)):
            if not start == save_list[i]:
                remains[start] = save_list[i]
            start = self.part_buffer[start][1]
        if not start == self.size:
            remains[start]=self.size
        return remains
    
class PPNetApp(PPApp):
    '''
    subclass should have self.process 
    '''    
            
    def __init__(self,station,app_id,callback=None):
        super().__init__(station,app_id,callback)
        self.waiting_list={}   #simple for app in one packet
        self.session_list={}   #  for multi packet process
        self.session_id = 0
            
    def start(self):
        '''
        could be overload
        '''
        super().start()
        self.station.set_app_process(self.app_id, self.process)        
        return self
    
    def quit(self):
        if self.station.get_app_process(self.app_id) == self.process:
            self.station.set_app_process(self.app_id, None)      
        super().quit()              
        pass
    
    def send_msg(self, peer_id, app_msg, need_ack=False, always=False):
        self.station.send_msg(peer_id, app_msg, need_ack, always)
        
    def waiting_reply(self,peer_id,app_msg):
        '''
        send with block and return msg
        '''
        app_id = app_msg.get("app_id")
        self.waiting_list[(peer_id,app_id)]=None
        self.send_msg(peer_id, app_msg, need_ack=True)
        loopcount = 0
        while loopcount < 500 and not self.waiting_list[(peer_id,app_id)]:
            time.sleep(0.1)
            loopcount += 1
        return self.waiting_list[(peer_id,app_id)]
    
    def session(self,peer_id,session_id,app_msg,size=0):
        '''
        session without block 
        '''
        if session_id==0:
            self.session_id +=1 
        real_session_id = session_id if not session_id==0 else self.session_id
        session = {"id":real_session_id,"size":size}
        app_msg.set_session(session)
#         logging.debug(app_msg.dict_data)        
        self.send_msg(peer_id, app_msg, need_ack=False)
        return real_session_id
    
    def waiting_session(self,peer_id,app_msg,parameter,size):
        '''
        session block and return data of given parameter
        '''
        session_id = self.session(peer_id=peer_id,session_id= 0 ,app_msg=app_msg,size=size)
        self.session_list[(peer_id,session_id)]=Block(block_id=parameter)
        self.send_msg(peer_id, app_msg, need_ack=False)
        
        loopcount = 0
        while loopcount < 500 and not self.session_list[(peer_id,session_id)].complete:
            time.sleep(0.1)
            loopcount += 1
        return self.session_list[(peer_id,session_id)].buffer        
        
    def process(self,msg, addr):
        '''
        need overload 
        '''
        app_msg = self.AppMessage(app_id = msg.get("app_id"),bindata = msg.get("app_data"))
#         app_msg = self.AppMessage(app_id = msg.get("app_id"),dictdata = msg.dict_data)
        logging.debug(app_msg.dict_data)
        session = app_msg.get_session()
        peer_id = app_msg.get("src_id")
        app_id = app_msg.get("app_id")
        if session:
            if (peer_id,session["id"]) in self.session_list:
                block = self.session_list[(peer_id,session["id"])]
                if "size" in session:
                    block.setInfo(size = session["size"],md5 = session["md5"])
                if "start" in session:
                    block.add(session["start"],session["end"],app_msg.get_parameter(block.block_id))
                pass
        if (peer_id,app_id) in self.waiting_list:
            self.waiting_list[(peer_id,app_id)] = app_msg.get("app_data")
        print(msg.dict_data,addr)
        pass
    
    
class PathRequester(PPNetApp):
    '''
    pr =  PathRequester(station)
    pr.request_path(node_id)
    '''
    
    class PathReqMessage(PPApp.AppMessage):
        '''
        old  pathreq       
            appid        appdata
             0002        [node_id,pathlimit,pathlen,id0,ip0,port0,nattype0,id1...ids ]
                                                 4      1,       1        4   4   2    1
        new:
            appid    appdata
            0002     cmd,tlv(node_id),tlv(pathlimit),tlv(pathlen),tlv(nodes)
                     nodes = [(id0,ip0,port0,nattype0,)id1...ids ]
                                                 
        command = "path_req":1,"path_res":2,"node_set":3,
        parameters =  "node_id":4,"path_limit":5,"path_len":6,"path":7
        path = [(id0,ip0,port0,nattype0),(id1...),...(ids...)]
        '''    
    
        def __init__(self, **kwargs):
            app_id = PP_APPID["PathReq"]
            tags_id= {"path_req":1,"path_res":2,"node_set":3,
                      "node_id":4,"path_limit":5,"path_len":6,"bin_path":7}
            tags_string={1:"path_req",2:"path_res",3:"node_set",
                         4:"node_id",5:"path_limit",6:"path_len",7:"bin_path"}
            parameter_type={4:"I",5:"B",6:"B",7:"s"},
            super().__init__(app_id,tags_id,tags_string,parameter_type,**kwargs)
        
        def load_path(self,bin_path,path_len):
            path  = []
            for i in range(0, path_len):
                noderesult = struct.unpack("IIHB", bin_path[i * 11:i * 11+11])
                path.append((noderesult[0],
                               socket.inet_ntoa(struct.pack('I', socket.htonl(noderesult[1]))),
                               noderesult[2],
                               noderesult[3]))
            return path
        
        def dump_path(self,path):
            data = b""
            for i in range(0, len(path)):
                node = path[i]
                nodedata = struct.pack("IIHB", node[0],
                                       socket.ntohl(struct.unpack("I", socket.inet_aton(node[1]))[0]),
                                       node[2], node[3])
                data += nodedata
            return data
       
        def load(self, bindata):
#             super().load(bindata)
#             self.dict_data["parameters"]["nodes"] = self.load_path(self.dict_data["parameters"]["bin_path"],
#                                                                   self.dict_data["parameters"]["path_len"])

            result = struct.unpack("IBB", bindata[:6])
            self.dict_data = {"parameters":{}}
            self.dict_data["parameters"]["node_id"] = result[0]
            self.dict_data["parameters"]["path_limit"] = result[1]
            self.dict_data["parameters"]["path_len"] = result[2]
            self.dict_data["parameters"]["nodes"] = self.load_path(bindata[6:],
                                                                  self.dict_data["parameters"]["path_len"])
            
            return self
        
        def dump(self):
            self.dict_data["parameters"]["bin_path"] = self.dump_path(self.dict_data["parameters"]["nodes"])
#             return super().dump()                        
            
            binlen = len(self.dict_data["parameters"]["bin_path"])
            data = struct.pack("IBB%ds"%binlen,
                               self.dict_data["parameters"]["node_id"],
                               self.dict_data["parameters"]["path_limit"],
                               self.dict_data["parameters"]["path_len"] ,
                               self.dict_data["parameters"]["bin_path"]
                               )
            return data

    def __init__(self,station):
        super().__init__(station,PP_APPID["PathReq"])
        pass

    def request_path(self, destid, path_limit=3, callback=None):

        if self.station.status:
            prmsg = self.PathReqMessage(dictdata={"command":"path_req",
                                                  "parameters":{
                                                        "node_id":destid, 
                                                        "path_limit":path_limit,
                                                        "path_len":1,
                                                        "nodes":[(self.station.node_id, self.station.ip, self.station.port, self.station.nat_type)]
                                                        }})
    
            self.send_msg(BroadCastId, prmsg)
            return True
            
        return False
    
    def process(self, ppmsg, addr):
        
        prmsg = PathRequester.PathReqMessage(bindata=ppmsg.get("app_data"))
        parameters = prmsg.get("parameters")
        path = parameters["nodes"]
        dst_node_id = parameters["node_id"]
        logging.debug(path)
        if dst_node_id in (self.station.node_id, BroadCastId):
            for i in range(0, len(path)):
                node_id = path[i][0]
                if node_id == self.station.node_id:
                    return  # discard ,must have been process
            # try source and first turn node ,connect and send pathresponse
            
            end = len(path) if len(path) < 2 else 2
            for i in range(0, end):
                node_id = path[i ][0]
                if node_id not in self.station.peers:
                    self.station.peers[node_id] = PPNode(node_id=node_id)
                node = self.station.peers[node_id]
                if not (node.ip,node.port) == (path[i ][1],path[i ][2]): 
                    node.load_dict({"ip": path[i ][1], "port":path[i ][2],
                                     "nat_type":NAT_TYPE["Turnable"],"turn_server":0})
                    self.station.set_status(node_id,False)
    #               # try send beat direct
                    self.station.beater.send_beat(node_id, "beat_req", is_try=True)
            # try beat src by turn node         
            peer = self.station.peers[path[0][0]]
            if end == 2 and path[1][1] not in ("0.0.0.0") and path[1][3] == NAT_TYPE["Turnable"]:
                peer.load_dict({"turn_server":path[1][0], "nat_type":NAT_TYPE["Unturnable"]})
                peer.load_dict({"ip":path[1][1], "port":path[1][2]})
                self.station.beater.send_beat(path[0][0], "beat_req", is_try=True)

        if (dst_node_id != self.station.node_id) or (dst_node_id == BroadCastId):            
            if len(path) >= parameters["path_limit"] or not self.station.nat_type == NAT_TYPE["Turnable"]:
                return  # exceed path_limit
            
            for i in range(0, len(path)):
                node_id = path[i][0]
                if node_id == self.station.node_id:
                    return  # self have been in path
            last_node_id = path[-1][0]
            path.append((self.station.node_id, self.station.ip, self.station.port, self.station.nat_type))
            
            prmsg.set("parameters",{"node_id":dst_node_id, 
                                    "path_limit":parameters["path_limit"],
                                    "path_len":len(path),
                                    "nodes":path})
            
            for node_id in self.station.peers:
                if self.station.peers[node_id].status and not last_node_id == node_id:
                    self.send_msg(node_id, prmsg)

class Session(object):
    '''
    run for bigdata 
    suppose  in one session 
    s = Session(send_process,receive_process)
    s.send()    
        will save buffer in send_buffer,if receive a reget request(session with data=b"") will send the buffer again
        return totalsize,send_pos
    s.receive()
        if data is b"" then resend the buffer
        if some packet miss will call send_process reget the data (session with data=b"")
        return totalsize,receive_pos
    
    '''
    def __init__(self,send_process,receive_process):
        self.send_process,self.receive_process = send_process,receive_process
        self.send_buffer={}  # {start:(data,end)}
        self.receive_buffer = {}  #{start:(data,end)}
        self.receive_pos = 0
        self.send_size = 0
        self.receive_size = 0
        
        self.last_get =  (0,0,0)  #(start,time,count)
        self.lock = threading.Lock()
        
    def send(self,session,data):
        '''
        return (size, pos)
        '''
        start = session["start"]
        session_id = session["id"]
        end = session["end"]
        if session["size"]:
            self.send_size =  session["size"]
            if start==self.send_size:
                return (self.send_size,end)
        if data:
            self.send_buffer[start] = (data,start+len(data))
        else:
            logging.info("some packet lost,resend %s,buffer %s"%(session,self.send_buffer.keys()))            
            #delete less packet
            for pos in list(self.send_buffer.keys()):
                if pos < start:
                    del self.send_buffer[pos]
            logging.debug("after,resend %s,buffer %s"%(session,self.send_buffer.keys()))
        if start in self.send_buffer:
            data = self.send_buffer[start][0]
            end = self.send_buffer[start][1]
            session = {"id":session_id,"size":0,"start":start,"end":end}
            self.send_process(session,data)

        return (self.send_size,end)
    
    def receive(self,session,data):
        '''
        return (size, pos)
        '''
        session_id = session["id"]
        start = session["start"]
        end = session["end"]

                        
        if not ( len(data) or (session["size"] and session["size"] == start)):  #reget self send
#             if self.send_size and not start == self.send_size:
            self.send(session,None)
            return (self.receive_size,self.receive_pos)

        if session["size"]:
            self.receive_size =  session["size"]
            logging.info("receive size %s pos %d"%(session,self.receive_pos))
            if  start == self.receive_size:
                return  (self.receive_size,self.receive_pos)
        
        logging.debug("%s pos:%d"%(session,self.receive_pos))
        
        if start < self.receive_pos:
            return (self.receive_size,self.receive_pos)
        
        self.receive_buffer[start]=(data,end) 
        next_start = self.receive_pos           
        if start > self.receive_pos:
            reget_session={"id":session_id,"size":self.receive_size,"start":self.receive_pos,"end":start}
            logging.warning("some packet drop,reget %s"%reget_session)
            now = time.time()
#             self.lock.acquire()
            if not self.last_get[0] == self.receive_pos or now - self.last_get[1] > 1:
                count = self.last_get[2]+1 if self.last_get[0] == self.receive_pos else 1
                if count < 5:
                    self.last_get = (self.receive_pos, now,count)
                    self.send_process(reget_session,b"")
                    return  (self.receive_size,self.receive_pos)
                else: #skip this packet
                    next_start = min(self.receive_buffer.keys())

#         self.receive_process(session, self.receive_buffer[self.receive_pos][0])
        while next_start in list(self.receive_buffer.keys()):
            next_end = self.receive_buffer[next_start][1]
            next_session = {"id":session_id,"size":0,"start":next_start,"end":next_end}
            self.receive_process(next_session,self.receive_buffer[next_start][0])
            del self.receive_buffer[next_start]
            next_start = next_end
        self.receive_pos = next_start
                    
        return  (self.receive_size,self.receive_pos)
#             self.lock.release()

    
class Texter(PPNetApp):
    '''
    texter =  Texter(station,callback)
    texter.send_text(node_id,text,echo,callback)
    
    callback(node_id,text)
    '''
    
    class TextMessage(PPApp.AppMessage):
        '''
        parameters = {
                "text":"test",}
        tm = TextMessage(dictdata={"command":"echo",
                                   "parameters":parameters} )
        bindata = tm.dump()
        tm1 = FileMessage(bindata=bindata)
        app_id = tm1.get("app_id")
        text = tm1.get("parameters")["text"]
        
        src_id   dst_id   app_id  sequence applen  appdata
        4byte    4byte    2byte   4byte   2byte   applen
        
        appid:     app        appdata
        0004       text       [cmd,paralen,tag,len,value,tag len value ...]
                                1    1     TLV
        cmd(parameters):
            echo(text)    1
            send(text)    2
        parameters(type,struct_type):
            text        string     s
        '''         
    
        def __init__(self, **kwargs):
            tags_id = {
              "echo":1,
              "send":2,
              "text":0x10,
              }
            tags_string = {
                1:"echo",
                2:"send",
                0x10:"text"}
            parameter_type = {0x10:"str"}
            super().__init__(app_id=PP_APPID["Text"],
                             tags_id=tags_id,
                             tags_string=tags_string,
                             parameter_type=parameter_type,
                             **kwargs)

           

    def __init__(self,station,callback=None):
        super().__init__(station,PP_APPID["Text"],callback)        
    pass
    
    def send_text(self, node_id, data, echo=False, callback=None):
        if echo:
            text_msg = self.TextMessage(dictdata={"command":"echo",
                                             "parameters":{"text":data}})
        else:
            text_msg = self.TextMessage(dictdata={"command":"send",
                                             "parameters":{"text":data}})
        if callback:
            self.set_callback(callback)           
        if node_id in self.station.peers or node_id == BroadCastId:
            self.send_msg(node_id, text_msg, need_ack=True)
        else:
            logging.warning("can't send data to %s" % node_id)        
        pass

    def process(self, ppmsg, addr):
        text_msg = self.TextMessage(bindata=ppmsg.get("app_data"))
        command = text_msg.get("command")
        text = text_msg.get("parameters")["text"]
        node_id = ppmsg.get("src_id")
        if command == "echo":
            self.send_text(node_id, text, echo=False)
        print(text)
        if self.callback:
            self.callback(node_id, text)

class Beater(PPNetApp):


    class BeatMessage(PPApp.AppMessage):
        '''
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
        timestamp: TLV
        
        dict_data={ 
                    command: 1,
                    parameters:{

                        node: {node_id,ip,port,nat_type,will_to_turn,secret}
                        peer: {node_id,ip,port,nat_type,will_to_turn,secret}
                        timestamp:
                        error_info:
                        }
                        
                    }
        '''
        

        def __init__(self, **kwargs):
            tags_id = {
              "beat_req":1,"beat_res":2,"beat_set":3,"offline":4,"find_node":5,"req_id":6,"res_id":7,
              "bin_node":0x10, "bin_peer":0x11,"bin_path":0x15,
              "net_id":0x12,"timestamp":0x13,"error_info":0x14}
            parameter_type = {0x10:"s",0x11:"s",0x15:"s",
                              0x12:"I",0x13:"I",0x14:"str"}
            super().__init__(app_id=PP_APPID["Beat"],
                             tags_id=tags_id,
                             tags_string=None,
                             parameter_type=parameter_type,
                             **kwargs)
        
        def load(self,bindata):
            super().load(bindata)
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
            pass
       
        def _load_node(self, bindata):
            node_info = {}
            result = struct.unpack("IIHBB8s", bindata)
            node_info["node_id"] = result[0]
            node_info["ip"] = socket.inet_ntoa(struct.pack('I', socket.htonl(result[1])))
            node_info["port"] = result[2]
            node_info["nat_type"] = result[3]
            node_info["will_to_turn"] = (result[4] == 1)
            node_info["secret"] = result[5].decode()
            return node_info
        
        def dump(self):
            if "node" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["bin_node"] = self._dump_node(self.dict_data["parameters"]["node"])
            if "peer" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["bin_peer"] = self._dump_node(self.dict_data["parameters"]["peer"])
            if "path" in self.dict_data["parameters"]:
                self.dict_data["parameters"]["bin_path"] = self._dump_path(self.dict_data["parameters"]["path"])
#             print(self.dict_data)
            return super().dump()
        
        def _dump_node(self, node_info):
            return struct.pack("IIHBB8s",
                               node_info["node_id"],
                               socket.ntohl(struct.unpack("I", socket.inet_aton(node_info["ip"]))[0]),
                               node_info["port"],
                               node_info["nat_type"],
                               1 if node_info["will_to_turn"] else 0,
                               node_info["secret"].encode(),)
            
        def _load_path(self,bin_path,path_len):
            path  = []
            for i in range(0, path_len):
                noderesult = struct.unpack("IIHB", bin_path[i * 11:i * 11+11])
                path.append((noderesult[0],
                               socket.inet_ntoa(struct.pack('I', socket.htonl(noderesult[1]))),
                               noderesult[2],
                               noderesult[3]))
            return path
        
        def _dump_path(self,path):
            data = b""
            for i in range(0, len(path)):
                node = path[i]
                nodedata = struct.pack("IIHB", node[0],
                                       socket.ntohl(struct.unpack("I", socket.inet_aton(node[1]))[0]),
                                       node[2], node[3])
                data += nodedata
            return data            
    pass

    def __init__(self,station,callback=None):
        super().__init__(station,PP_APPID["Beat"],callback)
        self.beat_count = 0
        self.beat_interval = 1        
        self.time_scale = 1
    
    def start(self):
        super().start()
        start_new_thread(self.beat, ())
        self.station.set_app_process(PP_APPID["Beat"], self.process)
        return self
        
    def beat(self):
        try:
            beated = False
            for peerid in self.station.peers:
                peer = self.station.peers[peerid]
                if peer.beat_interval > 3:
                    if peer.status:
                        logging.info("%s is offline." % peerid)
                    peer.status = False
                    peer.distance = 10
                    
                if self.beat_count % peer.beat_interval == 0:
                    peer.beat_interval = peer.beat_interval * 2 if  peer.beat_interval < 65 else 128
                    self.send_beat(peerid, beat_cmd="beat_req")
                    if not self._is_private_ip(peer.ip):
                        beated = True
                
            if not beated:
                self.beat_null()
        except:
            pass
            
        self.beat_count += 1 
        if not self.station.quitting:    
            self.timer = threading.Timer(60 * self.beat_interval*self.time_scale, self.beat)
            self.timer.start()
            self.no_beat = 0
            pass     
    
    def _direct_send(self,addr,dst_id,btmsg):
        msg = PPMessage(dictdata={"src_id":self.station.node_id,
                                  "dst_id":dst_id,
                                  "app_data":btmsg.dump(),
                                  "app_id":PP_APPID["Beat"],
                                  "sequence":0xffffffff})
        self.station._send(addr,msg.dump())
        
    def send_beat(self, peerid, beat_cmd="beat_req", is_try=False):
        
        now = time.time()
        if peerid not in self.station.peers:
            logging.warning("%d can't find %d,please try to find it first." %(self.station.node_id, peerid))
            return False
        
        peer = self.station.peers[peerid]

        if peer.ip == "0.0.0.0" or peer.ip == self.station.ip:
            return False 
        

        beat_dictdata = {"command":beat_cmd,
                         "parameters":{
                             "node":self.station.beat_info(),
                             "peer":peer.beat_info(),
                             "net_id":self.station.net_id,
                             "timestamp":int(time.time())
                             }}
        beat_msg = Beater.BeatMessage(dictdata=beat_dictdata)
            
        
        if beat_cmd == "offline":
            self.send_msg(BroadCastId, beat_msg, always=False)
        else:
            if now - peer.last_out > 10 or beat_cmd == "beat_res" or is_try:
#                 logging.debug("beat_msg %s"%beat_msg.dict_data)
                self.send_msg(peer.node_id, beat_msg, always=True)
                peer.last_out = int(now)
            if not peer.status and not is_try:
                self.station.path_requester.request_path(peer.node_id)

        return True
    
#     def send_beatV2(self,peerid, beat_cmd=_BEAT_CMD["beat_req"], is_try=False):
#         
    
    def process(self,msg,addr):
        '''
        #修改心跳者信息，若有更新的其他peer信息也同步修改
        #node is beat_src  peer is self
        '''
        btmsg = Beater.BeatMessage(bindata=msg.get("app_data"))   
#         logging.debug("%d receive btmsg %s from %s"%(self.station.node_id,btmsg.dict_data,"%s:%d"%addr))
        
#         net_id = btmsg.get("parameters")["net_id"]
#         if not self.station.net_id == PublicNetId and not net_id in (self.station.net_id,PublicNetId):
#             logging.warning("%d receive not same net beat,discard %s"%(self.station.node_id,net_id))
#             return

        distance = 7 - msg.get("ttl")     
        command = btmsg.get("command")
        parameters = btmsg.get("parameters")
        
        if "error_info" in parameters:
            logging.warning("%d encount beat error %s"%(self.station.node_id,parameters["error_info"]))
            return
            
        if command=="find_node":
            self.path_process(command,parameters)
            return
        
        if command in ("req_id",):
            node_id = self.set_peer_info(msg,addr) 
            if node_id:
                logging.debug("%d peer node_id %d"%(self.station.node_id,node_id))
                self.res_id(node_id, addr)
            
        if command in ("res_id",):
            self_info = parameters["peer"]
            if not self.station.node_id:
                self.station.node_id = self_info["node_id"]
                self.station.ip = self_info["ip"]
                self.station.port = self_info["port"]
                self.station.save_node_id()

        
        if command in ("beat_req","beat_res"):
            if parameters["peer"]["node_id"] == self.station.node_id:
                self.set_self_info(parameters["peer"],addr,distance)            
#             self.set_peer_info(command,parameters["node"],parameters["timestamp"],addr,distance,parameters)
            self.set_peer_info(msg,addr)        
        if command == "beat_req":
            self.send_beat(parameters["node"]["node_id"], beat_cmd="beat_res", is_try=True)
        return
         
    def beat_null(self):
        '''
        just keep nat firewall know it is runing
        '''
        self.station.sockfd.sendto(b"0",
                           (socket.inet_ntoa(struct.pack('I', socket.htonl(random.randint(1677721600, 1694498816)))),
                            random.randint(10000, 60000)))
        logging.debug("%d beat null"%self.station.node_id)   
        
    def send_offline(self):
        beat_dictdata = {"command":"offline",
                         "parameters":{
                                       "node":self.station.beat_info(),
                                       "peer":self.station.beat_info()
                                       }}
#         beat_dictdata["node"] = 
#         beat_dictdata["peer"] = self.station.beat_info()
        beat_msg = Beater.BeatMessage(dictdata=beat_dictdata)
        self.send_msg(BroadCastId, beat_msg, always=False)   
        
    def _is_private_ip(self, ip):
        if ip.startswith("172.") or ip.startswith("192.") or ip.startswith("10."):
            return True
        else:
            return False            
        
    def req_id(self):
        self.station.node_id = 0
        for peer_id in self.station.peers:
            self.send_beat(peer_id, beat_cmd="req_id", is_try=True)
        return 

    def res_id(self,node_id,addr):
        beat_dictdata = {"command":"res_id",
                         "parameters":{
                             "node":self.station.beat_info(),
                             "peer":self.station.peers[node_id].beat_info(),
                             "net_id":self.station.net_id,
                             "timestamp":int(time.time())
                             }}
        beat_msg = Beater.BeatMessage(dictdata=beat_dictdata)
        self._direct_send(addr, 0, beat_msg)
        self.station.delete_peer(node_id)
                
    def set_self_info(self,peer,addr,distance=1):
        if not peer["node_id"] == self.station.node_id \
            or peer["ip"] == "0.0.0.0" or self._is_private_ip(peer["ip"]):
            return
        if distance >1:
            if self.station.nat_type==NAT_TYPE["Unknown"] and distance < self.station.distance:
                self.station.nat_type = peer["nat_type"]
                self.station.distance = distance
                logging.debug("set self nattype to %s from undirect peer info" % NAT_STRING[self.station.nat_type])
            return
        if not self.station.status:
            self.station.ip = peer["ip"]
            self.station.port = peer["port"]
            nat_type = peer["nat_type"]
            if not nat_type == NAT_TYPE["Unknown"]:
                self.station.nat_type = nat_type
                self.station.distance = 1 
            logging.info("set self %d nattype to %s from peer!" %(self.station.node_id, NAT_STRING[self.station.nat_type]))
            self.station.status = True
            start_new_thread(self.station.publish,())
            self.station.last_beat_addr = addr
            logging.info("%s connect to the world." % self.station.node_id)
        else:
            if self.station.ip == peer["ip"] and self.station.port == peer["port"]:
                if not self.station.last_beat_addr == addr:
                    self.station.nat_type = NAT_TYPE["Turnable"] 
                    self.station.distance = 1 
                    logging.debug("set self %d nattype to %s for differen direct connect" %(self.station.node_id,
                                                                                NAT_STRING[self.station.nat_type]))
                    self.station.last_beat_addr = addr
            else:
                if self.station.ip == "0.0.0.0":
                    self.station.ip = peer["ip"]
                    self.station.port = peer["port"]
                    self.station.nat_type = peer["nat_type"]
                    logging.info("set self %d info to %s from peer!" % (self.station.node_id,
                                                            NAT_STRING[self.station.nat_type]))
                else:
                    self.station.nat_type = NAT_TYPE["Unturnable"]
                    self.station.distance = 1 
                    logging.debug("set self %d nattype to %s for not same ip port" % (self.station.node_id,
                                                                        NAT_STRING[self.station.nat_type]))
                    

#     def set_peer_info(self,command,node_info,timestamp,addr,distance,parameters=None):
    def set_peer_info(self,ppmsg,addr):
        btmsg = Beater.BeatMessage(bindata=ppmsg.get("app_data"))
        distance = 7 - ppmsg.get("ttl")     
        command = btmsg.get("command")
        parameters = btmsg.get("parameters")
        node_info = parameters["node"]
        node_id = node_info["node_id"]
        
        if node_id == 0 :
            if command == "req_id" and distance==1:
                node_id = self.station.get_free_id()
                node_info["node_id"] = node_id
                logging.debug("%d set peer node_id %d"%(self.station.node_id,node_id))
            else:
                return 0
        if node_id not in self.station.peers:
            self.station.peers[node_id] = PPNode(node_id=node_id)
                            
        peer = self.station.peers[node_id]
        peer.delay = (int(time.time() - parameters["timestamp"]) + peer.delay)/2
        if parameters:
            peer.net_id = parameters["net_id"]
        
        
        if command == "offline":
            peer.status = False
            peer.distance = 10
            logging.info("%s is offline." % node_id)
            return 0
       
        #wrong id
        if peer.status  and not self._is_private_ip(peer.ip) \
            and node_info["ip"] == "0.0.0.0":   
            parameters1 = {"error_info":"duplication node_id,maybe some one use the id.",
                          "net_id":self.station.net_id}
            
            btmsg = Beater.BeatMessage(dictdata={"command":"beat_res",
                                                   "parameters":parameters1 })  
            self._direct_send(addr=addr, dst_id=node_info["node_id"], btmsg=btmsg)      

            return 0
         
        if peer.distance < distance and peer.status:
            return 0
        
        if not peer.status:
            logging.info("%d: %s is online." %(self.station.node_id, node_id))
        
        peer.load_dict({"status":True, "beat_interval":1})

        # 部分nat 连接会更改端口
        if distance == 1:
            peer.load_dict(node_info)
            peer.load_dict({"ip":addr[0], "port":addr[1], "distance":distance,"turn_server":0})
            if node_info["ip"] == "0.0.0.0":
                self.send_beat(node_id, beat_cmd="beat_res", is_try=True)
        else:
            if distance < peer.distance :
                turn_id = self.station.get_peer_by_addr(addr)
                peer.load_dict({"ip":addr[0], "port":addr[1], "distance":distance,"turn_server":turn_id})
                
            if  node_info["nat_type"] in ( NAT_TYPE["Turnable"],NAT_TYPE["Unknown"]) \
                    and node_info["ip"] not in (peer.ip,"0.0.0.0",self.station.ip) \
                    and command == "beat_res" :
                old_node_info = peer.dump_dict()
                peer.load_dict(node_info)
                peer.load_dict({"nat_type":NAT_TYPE["Turnable"]})
                logging.info("peer turnable try to direct connect to : %d,%s,%d,%s" % (peer.node_id, peer.ip, peer.port, NAT_STRING[peer.nat_type]))
                self.send_beat(node_id, "beat_req", is_try=True)   
                peer.load_dict(old_node_info)
                peer.load_dict({"nat_type":NAT_TYPE["Unturnable"]})
                
            if  self.station.nat_type in (NAT_TYPE["Turnable"] ,NAT_TYPE["Unknown"]) \
                    and node_info["ip"] not in (peer.ip,"0.0.0.0",self.station.ip) \
                    and command == "beat_res" :
                old_node_info = peer.dump_dict()
                peer.load_dict(node_info)
                logging.info("self turnable try to direct connect to : %d,%s,%d,%s" % (peer.node_id, peer.ip, peer.port, NAT_STRING[peer.nat_type]))
                self.send_beat(node_id,"beat_req", is_try=True)   
                peer.load_dict(old_node_info)
                
            if peer.nat_type == NAT_TYPE["Unknown"]:
                peer.nat_type = node_info["nat_type"]
        return node_id
    
    
class NetManage(PPNetApp):
    '''
    net manage application
    net_manager  =  NetManage(station,callback)
    net_manager.get_stat(node_id)
    net_manager.set_stat(node_id,node_info)
    
    
    callback(node_id,node_info)
    '''
    class NMMessage(PPApp.AppMessage):
        '''
        parameters = {
                "node":100,}
        nm = NMMessage(dictdata={"command":"stat",
                                 "parameters":parameters} )
        bindata = nm.dump()
        nm1 = NMMessage(bindata=bindata)
        app_id = nm1.get("app_id")
        node = nm1.get("parameters")["node"]
        
        src_id   dst_id   app_id  sequence applen  appdata
        4byte    4byte    2byte   4byte   2byte   applen
        
        appid:     app        appdata
        00A1      netmanage       [cmd,paralen,tag,len,value,tag len value ...]
                                1    1     TLV
        cmd(parameters):
            get_stat(node)    1
            set_stat(node,stat)    2
            upgrade         3
        parameters(type,struct_type):
            node        int     I
            os          string  s
            nodes        [(nodeid,delay,bytesin,byteout,packetin,packetout),(nodeid,delay...)]
            files        [tlv(file1),tlv(file2)...]
            
            
        '''         
    
        def __init__(self, **kwargs):
            tags_id = {
              "stat_req":1,"stat_res":2,"stat_set":3,"upgrade":4,
              "node_id":0x10, "os":0x11,"nodes":0x12,"files":0x13,
              }
            parameter_type = {0x10:"I",0x11:"str",0x12:"s",0x13:"s"}
            super().__init__(app_id=PP_APPID["NetManage"],
                             tags_id=tags_id,
                             parameter_type=parameter_type,
                             **kwargs)
            
        def load(self,bindata):
            super().load(bindata)
            if "nodes" in self.dict_data["parameters"]:
                pass
            if "files" in self.dict_data["parameters"]:
                pass
            
        def dump(self):
            return super().dump()

           

    def __init__(self,station,callback=None):
        super().__init__(station,PP_APPID["NetManage"],callback)        
        self.callback_list={}
        pass
    
    def get_stat(self, node_id,callback=None):
        dictdata = {"command":"stat_req",
                    "parameters":{
                        "node_id":node_id,
                        }}
        nm_msg = self.NMMessage(dictdata=dictdata)
        if callback:
            self.callback_list[node_id]=callback
            self.send_msg(node_id, nm_msg, need_ack=True)
        else:
            stat = self.waiting_reply(node_id, nm_msg)
            if stat:
                print("%d os is %s"%(stat["node_id"],stat["os"]))
            return stat
    
    def reply_stat(self,node_id):
        os_info = json.dumps(platform.uname())
        dictdata = {"command":"stat_res",
                    "parameters":{
                        "node_id":self.station.node_id,
                        "os":os_info,
                        }}
        nm_msg = self.NMMessage(dictdata=dictdata)
        logging.debug("%d send netmanage message to %d"%(self.station.node_id,node_id))
        self.send_msg(node_id, nm_msg, need_ack=True)
        
    def process_stat_res(self,parameters):
        node_id = parameters["node_id"]     
        if node_id in self.callback_list:
            self.callback_list[node_id](parameters)
        else:
            self.waiting_list[(node_id,self.app_id)] = parameters
        pass   

    def process(self, ppmsg, addr):
        nm_msg = self.NMMessage(bindata=ppmsg.get("app_data"))
        command = nm_msg.get("command")
        parameters = nm_msg.get("parameters")
        node_id = ppmsg.get("src_id")
        if command == "stat_req":
            self.reply_stat(node_id)
        if command == "stat_res":
            self.process_stat_res(parameters)      
                  
class PPConnection(object):

    def __init__(self, station, callback=None):
        '''
        callback = (action,peer_id,action_content="",error_code=0,error_message="")
        '''

        self.station = station
        self.callback = callback
        self.peer_id = 0

    def connect(self, peer_id):
        '''
        '''
        if self.peer_id and not self.peer_id == peer_id:
            return None
        if not self.peer_id:
            if self.callback:
                self.callback("connect", peer_id)   
        self.peer_id = peer_id
     
        return self
        
    def disconnect(self, peer_id):
        '''
        '''
        self.peer_id = 0
        if self.callback:
            self.callback("diconnect", peer_id)
        return self      
    
    def send(self, app_msg, need_ack=False):
        if self.peer_id:
            self.station.send_msg(self.peer_id, app_msg, need_ack)
            
    def set_app_process(self, app_id, process=None):
        self.station.set_app_process(app_id, process)
    
    def finish(self, action, peer_id, action_content, error_code, error_message):
        print("%s with %d done return %d with %s " % (action, peer_id, error_code, error_message))

                                   
class PPStation(PPLinker):
    '''
    public 公布自己的信息，其他节点可以查询到自己状态
    will_to_turn 作为中转节点，如果自身是internet，fullcone，则其他节点可能通过该节点转发
    db_file 保存节点信息
    
    '''
    def __init__(self, config={}):
        if config:
            super().__init__(config = config,msg_callback=self.process_msg)
#             self.db_file = self.config.get("db_file","nodes.pkl")
            self.net_id = config.get("net_id", 0xffffffff)
        else:
            raise("Not correct config!")
        self.load_nodes(self.config)
        self.process_list = {}

        self.quitting = False
        self.path_requester = PathRequester(self)
        self.texter = Texter(self)
        self.beater = Beater(self)
        self.netmanage = NetManage(self)

        self.services.update({"beater":self.beater,"texter":self.texter,
                              "path_requester":self.path_requester,
                              "net_manage":self.netmanage})
        pass    

    def start(self):
        super().start()
        if not self.node_id:
            do_wait(self.beater.req_id,lambda: self.node_id,3)
        logging.info("Station %d is runing!"%self.node_id)
        return self        
        
    def quit(self):
        logging.info("Station is quitting...")
        if self.status:
            self.beater.send_offline()   
#         for service in self.services:
#             self.services[service].quit()
        self.dump_nodes()    
        super().quit()
        
    def get_free_id(self,check=False):
        max_id = max(self.peers.keys())
        '''
        check is it available 
        '''
        logging.debug(max_id)
        if not check:
            return max_id+1
        self.path_requester.request_path(max_id, 6, callback=None)
        time.sleep(2)
        if max_id not in self.peers:
            return max_id+1
        return self.get_free_id()
    
    def get_addr(self,port):
        temp_config = self.config.copy()
        temp_config.update({"node_port":port,"node_id":0})
        temp_station=PPStation(config = temp_config)
        temp_station.start()
        try_count = 0
        while not temp_station.node_id and try_count<10:
            temp_station.beater.req_id()
            time.sleep(1)
            try_count += 1
        temp_station.quit()
        if temp_station.node_id:
            return temp_station.local_addr,(temp_station.ip,temp_station.port)
        return None,None
        
    def get_peer_by_addr(self,addr):
        for peer_id in self.peers:
            if (self.peers[peer_id].ip,self.peers[peer_id].port) == addr and self.peers[peer_id].distance==1:
                return peer_id
        return 0
    
    def publish(self):
        # send self info to web directory
        if self.testing:
            return
        if  self.nat_type== NAT_TYPE["Turnable"] :  # ChangedAddressError:  #must
            payload = {"ip":self.ip, "port":self.port,  "node_id":self.node_id,"net_id":self.net_id}
            res = requests.post("http://ppnetwork.pythonanywhere.com/ppnet/public", params=payload)
            print(res.text)
        pass
    
    def get_peers_online(self):
        payload = {"net_id":self.net_id }
        response = requests.get("http://ppnetwork.pythonanywhere.com/ppnet/public", params=payload)
        peers = json.loads(response.text)
        peernodes = {}
        for peer in peers:
            if not int(peer) == self.node_id and peers[peer][0] and peers[peer][1]:
                peernodes[int(peer)] = PPNode(node_id=peer, ip=peers[peer][0], port=peers[peer][1]) 
        return peernodes   
    
    def get_status(self, node_id):
        if node_id in self.peers:
            return self.peers[node_id].status
        else:
            logging.warning("Can't found %d in peers." % node_id)
            return False

    def set_status(self,node_id,status):
        if node_id in self.peers and not status == self.peers[node_id].status:
            self.peers[node_id].set_status(status)
            for nid in self.peers:
                if self.peers[nid].turn_server == node_id:
                    self.set_status(nid, status)
#             if not status:
#                 self.beater.send_offline(node_id)        
    
    def set_app_process(self, appid, app_process):
        self.process_list[appid] = app_process
        pass
    
    def get_app_process(self, appid):
        return self.process_list[appid]
        pass    
   
    def _check_status(self):
        for peerid in self.peers:
            
            if self.peers[peerid].status:
                return True
                break
        return False

    def send_msg(self, peer_id, app_msg, need_ack=False, always=False):
        '''
        return sequence    0 if failure
        if need_ack must have ack,will retry 3 times if no_ack, then call ack_callback(sequence,False)
        ack_call back can be set by self.ack_callback = func  func(sequence,ackstatus) True have ack False else
        
        '''
        # 如果指定发送对象，则发给指定对象，如果未指定，则发送给节点中的所有 可连接节点
        # 检查是否在peers中，如果不在，
        if peer_id == BroadCastId:  # broadcast
            for peerid in self.peers:
                if self.peers[peerid].status:  # check_turnable():
                    self.send_msg(peerid, app_msg, False, always)
        else:  # unicast
            if peer_id in self.peers:
                peer = self.peers[peer_id]
                app_data = app_msg.dump()
                ppmsg = PPMessage(dictdata={"net_id":self.net_id,"src_id":self.node_id, "dst_id":peer.node_id,
                                            "app_data":app_data, "app_len":len(app_data),
                                            "app_id":app_msg.get("app_id")})
#                 if peer.status or always:
                return self.send_ppmsg(peer, ppmsg, need_ack)
            if peer_id == self.node_id:
                return 0
            print("can't communicate to %s" % peer_id)
            return 0

    def forward_ppmsg(self, peer_id, pp_msg ):
        '''
        forward to peer or broadcase ,    ttl 减一
        
        '''
        ttl = pp_msg.get("ttl")
        if ttl == 0:
            return
        if peer_id == BroadCastId:  # broadcast
            for peerid in self.peers:
                if self.peers[peerid].status:  # check_turnable():
                    pp_msg.set("ttl",ttl)
                    self.forward_ppmsg(peerid, pp_msg)
        else:  # unicast
            if peer_id in self.peers:
                peer = self.peers[peer_id]
                pp_msg.set("ttl",ttl-1)
                return self.send_ppmsg(peer, pp_msg)
            if peer_id == self.node_id:
                return 0
            print("can't communicate to %s" % peer_id)
            return 0        
    
    def process_msg(self, ppmsg, addr):
        
        dst_id = ppmsg.get("dst_id")
        if dst_id == self.node_id or dst_id == BroadCastId:
            src_id = ppmsg.get("src_id")
            app_id = ppmsg.get("app_id")
            if src_id in self.peers:
                peer = self.peers[src_id]
                peer.last_in = int(time.time())
                peer.byte_in += len(ppmsg.get("app_data")) + 20
                peer.packet_in += 1

                if not app_id == PP_APPID["Beat"] :
                    # peer.status = True
                    peer.beat_interval = 1
                  
            process = self.process_list.get(ppmsg.get("app_id"), None)
            
            if process :  # and sequence > self.peers[src_id].rx_sequence:
                process(ppmsg, addr)     
#             else:
#                 logging.warning("%s no process seting for %s"%(self.node_id,ppmsg.get("app_id")))
            else:  #if dst_id == BroadCastId:  #unknown app,just forward to peers ,try forward to dst_id
                self.forward_ppmsg(dst_id, ppmsg)

        else:
            if dst_id in self.peers:
                logging.debug("%d forward to %s " % (self.node_id, str(dst_id)))
                ttl = ppmsg.get("ttl") - 1 
                if ttl & 0x0f > 0:
                    ppmsg.set("ttl", ttl)
                    self.send_ppmsg(self.peers[dst_id], ppmsg)
                    self.byte_turn += len(ppmsg.get("app_data")) + 20
                    self.packet_turn += 1
        pass
    
    def delete_peer(self,peer_id):
        if peer_id in self.peers:
            self.peers.pop(peer_id)
        
    def set_ipport(self, peer_id, ip, port):
        if peer_id not in self.peers:
            self.peers[peer_id] = PPNode(node_id = peer_id)        
        self.peers[peer_id].ip = ip
        self.peers[peer_id].port = port
        self.peers[peer_id].nat_type = NAT_TYPE["Unturnable"]

        self.set_status(peer_id,False)
        self.beater.send_beat(peer_id, beat_cmd = "beat_req", is_try=True)            
                    
    def set_route(self, peer_id, turn_id):
        if peer_id not in self.peers:
            self.peers[peer_id] = PPNode(node_id = peer_id)
        if turn_id in self.peers and peer_id in self.peers:
            self.peers[peer_id].turn_server = turn_id
            self.set_ipport(peer_id, self.peers[turn_id].ip, self.peers[turn_id].port)
        
    def get_all_nodes(self, delay=2):
        print("Self Info:\n%s\nPeers Info:" % self)
        for peerid in self.peers:
            print(self.peers[peerid])
            
        return self.peers
    
    def dump_nodes(self):
#        pickle.dump( self.peers, open( self.db_file, "wb" ) ) 
        with open(self.db_file, "w") as f:
#             print(self.json_nodes())
            f.write(json.dumps(self._dump_nodes_to_dict()))
        pass
    
    def save_node_id(self):
        if "config_file"  in self.config:
            cf = open(self.config["config_file"],"w")
            yaml.dump({"node_id":self.node_id},cf)
        return
    
    def json_nodes(self, detail=False):
        nodes_dict = {}
        for peer in self.peers:
            nodes_dict["%d"%peer] = self.peers[peer].dump_dict(detail)
#         nodes_dict[self.node_id] = self.dump_dict(detail)
        
        return json.dumps(nodes_dict)
    
    def _dump_nodes_to_dict(self,detail=False):
        nodes_dict = {}
        for peer in self.peers:
            nodes_dict["%d"%peer] = self.peers[peer].dump_dict(detail)     
        return nodes_dict   
    
    def load_nodes(self,config):
        self.peers = {}        
        if "node_file" in config:
            self.db_file = config["node_file"]
            self._load_nodes_from_file(self.db_file)
        else:
            self.db_file = "nodes.pkl"
        if "nodes" in config:
            self._load_nodes_from_dict(config["nodes"])
        if not self.peers:
            print("load peer online:")
            self.peers = self.get_peers_online()            
        logging.debug(self.db_file)
#         logging.debug(self.json_nodes())

    def _load_nodes_from_dict(self,nodes_dict):
        logging.debug(nodes_dict)
        for node in nodes_dict:
            self.peers[node] = PPNode().load_dict(nodes_dict[node])
            self.peers[node].beat_interval = 1
            if self.node_id in self.peers:
                del self.peers[self.node_id]
                            
    def _load_nodes_from_file(self,filename):            
        try:
            with open(filename, "rt") as f:
                nodes = json.loads(f.read())
                nodes1 = {}
                for node in nodes:
                    nodes1[int(node)] = nodes[node]
                self._load_nodes_from_dict(nodes1)
        except IOError:
            logging.warning("can't load nodes from %s" % self.db_file)
    
    def wait_status(self,node_id,timeout=5):
        count = 0
        while not self.get_status(node_id):
            time.sleep(1)
            count += 1
            if count>timeout:
                break
        return self.get_status(node_id)
    
    def support_commands(self):
        return ["beat","find","p2p","cast","route","ipport","help","quit","stat","set","control"]
    
    def run_command(self,command_string):
        cmd = command_string.split(" ") 
        #
        if cmd[0]=="beat" and len(cmd)>=2:
            node_id = int(cmd[1])
            self.beater.send_beat(node_id,"beat_req", is_try=True)
            if self.wait_status(node_id, timeout=3):
                self.texter.send_text(node_id,str(node_id)+" is online!",echo=True)
            else:
                print("%d is offline!"%(node_id))
        elif cmd[0]=="find" and len(cmd)>=2:
            node_id = int(cmd[1])
            self.path_requester.request_path(node_id)
            time.sleep(2)
            if node_id in self.peers:
                print(self.peers[node_id])
            else:
                print("can't find path to %d"%node_id)
        elif cmd[0]=="p2p" and len(cmd)>=3:
            self.texter.send_text(int(cmd[1]),command_string[5+len(cmd[1]):])
        elif cmd[0]=="cast":
            self.texter.send_text(0xffffffff,command_string[5:])
        elif cmd[0]=="route" and len(cmd)>=3:
            self.set_route(peer_id=int(cmd[1]), turn_id= int(cmd[2]))
        elif cmd[0]=="ipport" and len(cmd)>=4:
            self.set_ipport(peer_id=int(cmd[1]), ip= cmd[2],port = int(cmd[3]))            
        elif cmd[0]=="set" and len(cmd)>=3 and cmd[1]=="nattype":
            self.nat_type = int(cmd[2])                
        elif cmd[0]=="control" and len(cmd)>=2 and cmd[1]=="publish":
            self.publish()                  
        elif cmd[0]=="stat":
            if len(cmd) == 2:
                peer_id = int(cmd[1])
                if peer_id == self.node_id:
                    print(self.dump_dict(detail = True))
                else:
                    print(self.peers[peer_id].dump_dict(detail = True))
            else:
                self.get_all_nodes(delay=0)
                print("Services:",self.services.keys())
        elif cmd[0]=="help":
            response = requests.get("http://ppnetwork.pythonanywhere.com/ppnet/help.txt")
            print(response.text.encode(response.encoding).decode())      
        elif cmd[0]=="quit":
            self.quit()
        else:
            return False
        return True

    
def main(config):
    print("PPNetwork is lanching...")
    station = PPStation(config=config)
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
    node_type = config.get("node_type","server")
    is_client = node_type == "client"
    while not is_client and not station.quitting:
        time.sleep(3)
        
    s= "help"
    while not station.quitting:
        try:
            station.run_command(s)
            print("\n%d>"%station.node_id,end="")
        except Exception as exp:
            print(exp.__str__())
        if not station.quitting:
            s=input()

    print("PPNetwork Quit!")
    


if __name__ == '__main__':
    config = {"auth_mode":"secret", "secret":"password",
                   "share_folder":".", "net_id":PublicNetId,
                   "pp_net":"home", "node_id":100,
                   "node_port":54320, "DebugLevel":logging.WARNING}
    config = yaml.load(open("fmconfig.yaml"))
    set_debug(config.get("DebugLevel", logging.WARNING),
              config.get("DebugFile", ""))

    main(config=config)
    
    pass

