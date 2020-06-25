# coding=utf-8 
'''
Created on 2018年2月28日

@author: heguofeng

todo:
用dh 交换，加密

'''
import binascii
import hashlib
import json
import logging
import platform
import threading
import time

from ppnet.common import set_debug, packaddr
from ppnet.config import PublicNetId, BroadCastId
from ppnet.ppl1node import PPLayer
from ppnet.ppl2node import PPApp, PP_APPID, PPNetApp
from ppnet.ppl3node import PPL3Node


class Block(object):
    def __init__(self, block_id="", buffer=b""):
        self.pos = 0
        self.size = 0
        self.mtime = int(time.time())
        self.load(block_id, buffer)
        self.buffer = None
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
        """
        need override for sub class
        """
        self.block_id = file_name
        with open(file_name, mode) as f:
            buffer = f.read()
        self.load(self.block_id, buffer)
        return self

    def load_buffer(self):
        """
        for continue transfer  after failure
        return file_md5,file_size,received_bytes,unreceived blocks dictionay
        {start1:end1,...startn,endn}
        """
        return "", 0, 0, {}

    def save_buffer(self, file_md5, file_size, received_bytes, buffer):
        """
        for continue transfer  after failure
        return unreceived blocks dictionay
        {start1:end1,...startn,endn}
        """
        return

    def seek(self, start, mode=0):
        """
        0 from begin
        """
        self.pos = start if start < self.size else self.size

    def read(self, byte_count):
        end = self.pos + byte_count if self.pos + byte_count < self.size else self.size
        return self.buffer[self.pos:end]

    def write(self, bindata):
        front = self.pos if self.pos > self.size else self.size
        tail = self.pos + len(bindata) if self.pos + len(bindata) < self.size else self.size
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

    def setInfo(self, size, md5=b""):
        self.size = size
        self.md5 = md5
        self.part_buffer = {}
        self.complete = False

    def addPart(self, start, end, data):
        if end not in self.part_buffer:
            self.part_buffer[start] = (end, data)
        else:
            buffer1 = self.part_buffer[end]
            self.part_buffer[start] = (buffer1[0], data + buffer1[1])
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
            remains[start] = self.size
        return remains


class Session(object):
    """
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

    """

    def __init__(self, send_process, receive_process):
        self.send_process, self.receive_process = send_process, receive_process
        self.send_buffer = {}  # {start:(data,end)}
        self.receive_buffer = {}  # {start:(data,end)}
        self.receive_pos = 0
        self.send_size = 0
        self.receive_size = 0

        self.last_get = (0, 0, 0)  # (start,time,count)
        self.lock = threading.Lock()

    def send(self, session, data):
        """
        return (size, pos)
        """
        start = session["start"]
        session_id = session["id"]
        end = session["end"]
        if session["size"]:
            self.send_size = session["size"]
            if start == self.send_size:
                return (self.send_size, end)
        if data:
            self.send_buffer[start] = (data, start + len(data))
        else:
            logging.info("some packet lost,resend %s,buffer %s" % (session, self.send_buffer.keys()))
            # delete less packet
            for pos in list(self.send_buffer.keys()):
                if pos < start:
                    del self.send_buffer[pos]
            logging.debug("after,resend %s,buffer %s" % (session, self.send_buffer.keys()))
        if start in self.send_buffer:
            data = self.send_buffer[start][0]
            end = self.send_buffer[start][1]
            session = {"id": session_id, "size": 0, "start": start, "end": end}
            self.send_process(session, data)

        return (self.send_size, end)

    def receive(self, session, data):
        """
        return (size, pos)
        """
        session_id = session["id"]
        start = session["start"]
        end = session["end"]

        if not (len(data) or (session["size"] and session["size"] == start)):  # reget self send
            #             if self.send_size and not start == self.send_size:
            self.send(session, None)
            return (self.receive_size, self.receive_pos)

        if session["size"]:
            self.receive_size = session["size"]
            logging.info("receive size %s pos %d" % (session, self.receive_pos))
            if start == self.receive_size:
                return (self.receive_size, self.receive_pos)

        logging.debug("%s pos:%d" % (session, self.receive_pos))

        if start < self.receive_pos:
            return self.receive_size, self.receive_pos

        self.receive_buffer[start] = (data, end)
        next_start = self.receive_pos
        if start > self.receive_pos:
            reget_session = {"id": session_id, "size": self.receive_size, "start": self.receive_pos, "end": start}
            logging.warning("some packet drop,reget %s" % reget_session)
            now = time.time()
            #             self.lock.acquire()
            if not self.last_get[0] == self.receive_pos or now - self.last_get[1] > 1:
                count = self.last_get[2] + 1 if self.last_get[0] == self.receive_pos else 1
                if count < 5:
                    self.last_get = (self.receive_pos, now, count)
                    self.send_process(reget_session, b"")
                    return (self.receive_size, self.receive_pos)
                else:  # skip this packet
                    next_start = min(self.receive_buffer.keys())

        #         self.receive_process(session, self.receive_buffer[self.receive_pos][0])
        while next_start in list(self.receive_buffer.keys()):
            next_end = self.receive_buffer[next_start][1]
            next_session = {"id": session_id, "size": 0, "start": next_start, "end": next_end}
            self.receive_process(next_session, self.receive_buffer[next_start][0])
            del self.receive_buffer[next_start]
            next_start = next_end
        self.receive_pos = next_start

        return (self.receive_size, self.receive_pos)


#             self.lock.release()


class Texter(PPNetApp):
    """
    texter =  Texter(station,callback)
    texter.send_text(node_id,text,echo,callback)

    callback(node_id,text)
    """

    class TextMessage(PPApp.AppMessage):
        """
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
        """

        def __init__(self, **kwargs):
            tags_id = {
                "echo": 1,
                "send": 2,
                "text": 0x10,
            }
            tags_string = {
                1: "echo",
                2: "send",
                0x10: "text"}
            parameter_type = {0x10: "str"}
            super().__init__(app_id=PP_APPID["Text"],
                             tags_id=tags_id,
                             tags_string=tags_string,
                             parameter_type=parameter_type,
                             **kwargs)

    def __init__(self, callback=None):
        super().__init__(PP_APPID["Text"], callback)

    pass

    def send_text(self, node_id, data, echo=False, callback=None):
        if echo:
            text_msg = self.TextMessage(dictdata={"command": "echo",
                                                  "parameters": {"text": data}})
        else:
            text_msg = self.TextMessage(dictdata={"command": "send",
                                                  "parameters": {"text": data}})
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


class PPDataer(PPLayer):
    """
    dataer =  PPDataer(ppl3node)
    dataer.send(data,node_id)

    callback(node_id,text)
    """

    def __init__(self, underlayer=None):
        super().__init__(underlayer)

    def send(self, data, addr):
        self._underlayer.dataer.send_data(data, addr)

    def receive(self, count=1522):
        return self._underlayer.dataer.receive_data(count)

    def process(self, data, addr):
        logging.debug("receive data from {0} :{1}\n ".format(addr,
                                                             ''.join('{:02x} '.format(x) for x in data[:16])))
        if self.callback:
            self.callback(data, addr)


class PPDataNode(PPDataer):
    def __init__(self, config={"node_port": 0, "node_id": b"\0" * 6}):
        l3node = PPL3Node(config)
        super().__init__(l3node)
        l3node.dataer.callback = self.process

    def wait_receive(self, callback):
        self.set_callback(callback)

    @property
    def node_id(self):
        return self.underlayer.node_id

    @node_id.setter
    def node_id(self, id=None):
        """
        set node_id
        :param id: bytes or addr tuple(ip,port)
        :return:
        """
        if isinstance(id, bytes):
            self.underlayer.node_id = id
        elif isinstance(id, tuple):  # addr=(ip,port)
            self.underlayer.node_id = packaddr(id)
        self.underlayer.beater.rebeat()

    @property
    def sockname(self):
        return (self._underlayer.ip, self._underlayer.port)

    @property
    def sock(self):
        return self.underlayer.underlayer.sock

    def set_peer(self, peer_addr):
        node_id = packaddr(peer_addr)
        if node_id not in self.underlayer.peers:
            self.underlayer.set_ipport(node_id, peer_addr[0], peer_addr[1])
        return node_id


class NetManage(PPNetApp):
    """
    net manage application
    net_manager  =  NetManage(station,callback)
    net_manager.get_stat(node_id)
    net_manager.set_stat(node_id,node_info)


    callback(node_id,node_info)
    """

    class NMMessage(PPApp.AppMessage):
        """
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


        """

        def __init__(self, **kwargs):
            tags_id = {
                "stat_req": 1, "stat_res": 2, "stat_set": 3, "upgrade": 4,
                "node_id": 0x10, "os": 0x11, "nodes": 0x12, "files": 0x13,
            }
            parameter_type = {0x10: "I", 0x11: "str", 0x12: "s", 0x13: "s"}
            super().__init__(app_id=PP_APPID["NetManage"],
                             tags_id=tags_id,
                             parameter_type=parameter_type,
                             **kwargs)

        def load(self, bindata):
            super().load(bindata)
            if "nodes" in self.dict_data["parameters"]:
                pass
            if "files" in self.dict_data["parameters"]:
                pass

        def dump(self):
            return super().dump()

    def __init__(self, station, callback=None):
        super().__init__(station, PP_APPID["NetManage"], callback)
        self.callback_list = {}
        pass

    def get_stat(self, node_id, callback=None):
        dictdata = {"command": "stat_req",
                    "parameters": {
                        "node_id": node_id,
                    }}
        nm_msg = self.NMMessage(dictdata=dictdata)
        if callback:
            self.callback_list[node_id] = callback
            self.send_msg(node_id, nm_msg, need_ack=True)
        else:
            stat = self.waiting_reply(node_id, nm_msg)
            if stat:
                print("%d os is %s" % (stat["node_id"], stat["os"]))
            return stat

    def reply_stat(self, node_id):
        os_info = json.dumps(platform.uname())
        dictdata = {"command": "stat_res",
                    "parameters": {
                        "node_id": self.station.node_id,
                        "os": os_info,
                    }}
        nm_msg = self.NMMessage(dictdata=dictdata)
        logging.debug("%d send netmanage message to %d" % (self.station.node_id, node_id))
        self.send_msg(node_id, nm_msg, need_ack=True)

    def process_stat_res(self, parameters):
        node_id = parameters["node_id"]
        if node_id in self.callback_list:
            self.callback_list[node_id](parameters)
        else:
            self.waiting_list[(node_id, self.app_id)] = parameters
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
        """
        callback = (action,peer_id,action_content="",error_code=0,error_message="")
        """

        self.station = station
        self.callback = callback
        self.peer_id = 0

    def connect(self, peer_id):
        """
        """
        if self.peer_id and not self.peer_id == peer_id:
            return None
        if not self.peer_id:
            if self.callback:
                self.callback("connect", peer_id)
        self.peer_id = peer_id

        return self

    def disconnect(self, peer_id):

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


def main(config):
    print("PPData Network is lanching...")
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
