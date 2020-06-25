# coding=utf-8 
'''
Created on 2018年4月5日

@author: heguofeng
'''
import unittest
from pp_control import PPNetApp,  Beater
import socket
import logging
from _thread import start_new_thread
from pp_link import PP_APPID,  NAT_TYPE,  PPMessage,\
    do_wait
import struct
import time
import threading
import random
import select
import sys

def prepare_socket(timeout=10,ip="0.0.0.0",port=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if not sys.platform.startswith("win"):    
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if timeout:
        sock.settimeout(timeout)
    if port:            
        sock.bind((ip,port))
    return sock

class Flow(PPNetApp):
    '''
    if is a process node,should define out_process(client_sock,client_addr,session) 
    self.output_process,(client_sock,client_addr,session)
    1\add to beat node,get self ip
    2\stop beat,start datalayer
    3\
    sessions session pool 
    '''
    
    class DataMessage(PPNetApp.AppMessage):
        def __init__(self,**kwargs):
            tags_id={"addr_req":1,"addr_res":2,"connect_req":20,"connect_res":21,"disconnect":22,
                     "ip":3,"port":4,"peer_ip":5,"peer_port":6,"node_id":7,
                     "session_src":11,"session_dst":12,"session_id":13}
            parameter_type = {3:"str",4:"I",5:"str",6:"I",7:"I",
                              11:"I",12:"I",13:"I"}
            super().__init__( app_id=PP_APPID["Data"], 
                            tags_id=tags_id,
#                              tags_string=tags_string,
                            parameter_type=parameter_type,**kwargs)
                
    def __init__(self,station,config):
        '''
        [client_sock,remote_sock,failurecount,client_sock_type,remote_sock_type]
        sock_type  means terminal sock or exchange_sock. terminal sock no need ack
                        acked_sock or need_ack_sock
        '''
        super().__init__(station, app_id=PP_APPID["Data"], callback=None)
        self.sessions = {}  # {(src_id,dst_id,session_id):[client_sock,need-ack ,failurecount]}
        self.session_id = 0
        self.external_addr = None
        self.flow_port = config.get("flow_port",7000)
        self.session_limit = config.get("session_limit",1000)
        self.local_addr = ("0.0.0.0",self.flow_port)
        
        self.quitting = False
        self.timer = None
        self.servsock = None
        self.count = 0   #active sessions 
        self.exchange_nodes = {}  # {nodeid:addr,}
        self.input_process = None
        self.output_process = None
        self.send_in_minute = False   # if send packet will set the send_in_minut true, it will clear by timer
    
    def start(self):
        super().start()        
        self.get_self_addr()
#         if not self.external_addr:
#             return None

        self.quitting = False
        self.count = 0
        self.servsock = prepare_socket(timeout=0,port=self.flow_port)
        logging.info("datalayer: --> %s:%d -->" % ('0.0.0.0',self.flow_port))        
        self.servsock.listen(self.session_limit)
        start_new_thread(self.listen, ())
        start_new_thread(self.check, ())
        return self

    def quit(self):
        self.quitting = True
        if self.timer:
            self.timer.cancel()
            self.timer = None
        if self.servsock:
            self.servsock.close()
            self.servsock = None    
        super().quit()
            
    def check(self):
        
        for s_id in list(self.sessions.keys()):
            if not self.sessions[s_id][0]:
                self.sessions[s_id][2] += 1
                if self.sessions[s_id][2] > 2:
                    self.sessions.pop(s_id)
            elif self.sessions[s_id][0].fileno() <0 :
                self.sessions.pop(s_id)
                
        if not self.send_in_minute:
            start_new_thread(self.connect_out,())
                        
        if not self.quitting:
            self.send_in_minute = False
            self.timer = threading.Timer(60, self.check)
            self.timer.start()
               
    def connect_out(self):
        '''
        just keep nat firewall know it is runing
        '''
        logging.debug("flow connect out")
        try:
            sock = prepare_socket(timeout=1,port=self.flow_port)
            sock.connect((socket.inet_ntoa(struct.pack('I', socket.htonl(random.randint(1677721600, 1694498816)))),
                                random.randint(10000, 60000)))
        except socket.timeout:
            pass
        except:
            logging.exception("flow connect out error")
        finally:
            sock.close()   

    def get_self_addr(self,):
        local_addr,external_addr = self.station.get_addr(self.flow_port)
        if external_addr:
            self.external_addr = external_addr
            self.local_addr = local_addr
            logging.info("get self external_addr %s:%d"%self.external_addr)
        else:
            if self.station.status and self.station.nat_type==NAT_TYPE["Turnable"]:
                self.external_addr = (self.station.ip,self.flow_port)
                self.local_addr = (self.station.local_addr[0],self.flow_port)
                logging.info("get self external_addr %s:%d by guess"%self.external_addr)
            else:
                logging.error("can't get external address,quit")                
            return                      

    def listen(self,):
        while not self.quitting:
            try:
                client_sock, client_addr = self.servsock.accept()
            except Exception as exp:
                logging.warning(exp)
                continue
            else:
                logging.debug("accept new connect %s %s"%(client_sock,client_addr))
                self.send_in_minute = True
                start_new_thread(self.session_process,(client_sock,client_addr,True,True))   

    def send_peer_info(self,sock,session):
        '''
        session = (session_src,session_dst,session_id)
        '''
        if sock and sock.fileno()>0:
            peer_addr = sock.getpeername()
            data =  PPMessage.packip(peer_addr[0])
            data += struct.pack("I",peer_addr[1])
            data += struct.pack("I",session[0])
            data += struct.pack("I",session[1])        
            data += struct.pack("I",session[2])
            sock.sendall(data)
        else:
            logging.warning("sock error %s"%sock)
        return 
        pass
    
    def get_peer_info(self,sock,is_accept=False):
        try:
            sock.settimeout(10)
            data = sock.recv(20)
            logging.debug("receive data(%d) %s"%(len(data),data))
            if len(data)<20:
                return None
            info = {"ip":Beater.BeatMessage.unpackip(data[0:4]),
                    "port":struct.unpack("I",data[4:8])[0],
                    "session_src":struct.unpack("I",data[8:12])[0],
                    "session_dst":struct.unpack("I",data[12:16])[0],
                    "session_id":struct.unpack("I",data[16:20])[0]}
            if is_accept and not self.external_addr:
                self.external_addr = (info["ip"],info["port"])
            return info 
        except Exception as exp:
            logging.debug("get peer_info return error %s"%exp)
            return None
        
    def pop_session(self,session):
        if session in self.sessions:
            sock = self.sessions[session][0]
            self.sessions.pop(session)
            return sock
        return None
        
    def session_process(self,client_sock,client_addr,need_ack=False,is_accept=False):
        '''
        add socket to session,if socket have output process
        if socket have a connect already, proxy it
        '''
#         if client_addr in self.exchange_nodes.values():
        if True:
            info = self.get_peer_info(client_sock,is_accept)
            if info: 
                session = (info["session_src"],info["session_dst"],info["session_id"])
                if self.station.node_id in (session[0],session[1]):  # 无论源或目的 
                    if session not in self.sessions:
                        self.sessions[session]=[client_sock,need_ack,0]
                    if need_ack:
                        self.send_peer_info(client_sock, session)
                    if self.output_process :                            
                        start_new_thread(self.output_process,(client_sock,client_addr,session))
                else:  # turn node 
                    if session not in self.sessions:
                        self.sessions[session]=[client_sock,need_ack,0]
                    else:
                        if need_ack:
                            self.send_peer_info(client_sock, session)
                        if self.sessions[session][1]:
                            self.send_peer_info(self.sessions[session][0], session)
                        start_new_thread(self.exchange,
                            (self.sessions[session][0],client_sock))
            else:
                logging.debug("can't get peer info")
                pass 
 

    def req_connect(self,peer_id,dst_id,session):
        dictdata = {"command":"connect_req",
                    "parameters":{
#                       "ip":addr[0],
                      "node_id":dst_id,
                      "session_src":session[0],
                      "session_dst":session[1],
                      "session_id":session[2]}}
        logging.debug(dictdata)
        self.send_msg(peer_id, Flow.DataMessage(dictdata=dictdata))
        
        return
    
    def req_disconnect(self,dst_id,session):
        dictdata = {"command":"connect_req",
                    "parameters":{
                      "node_id":dst_id,
                      "session_src":session[0],
                      "session_dst":session[1],
                      "session_id":session[2]}}
        logging.debug(dictdata)
        self.send_msg(dst_id, Flow.DataMessage(dictdata=dictdata))
        
        return    
        
    def connect(self,peer_id,session=None,isResponse=False):
        if peer_id in self.station.peers:
            if not session:
                self.session_id += 1
                session = (self.station.node_id,peer_id,self.session_id)  
            peer = self.station.peers[peer_id]
            if peer.nat_type == NAT_TYPE["Turnable"]:
                try:
                    addr = self.get_addr(peer_id)
                    logging.debug("try connect to %s"%("%s:%d"%addr if addr else "None"))
                    if addr:
                        sock = prepare_socket(timeout=5)
                        sock.connect(addr)
                        self.send_peer_info(sock, session)
                        self.session_process(sock, self.exchange_nodes[peer_id],need_ack=False)
                    else:
                        return None
                except:
                    logging.exception("connect %d error nodes with %s"%(peer_id,self.exchange_nodes))

                    return None
                return session

            else:
                if self.station.nat_type == NAT_TYPE["Turnable"]:
                    if not isResponse:
                        self.req_connect(peer_id, self.station.node_id, session)
                        time.sleep(2)
                        return session
                else: #turn server
                    turn_id = peer.turn_server
                    if not isResponse:
                        self.req_connect(peer_id, turn_id, session)
                    return self.connect(peer_id=turn_id,session=session)
        else:                
            logging.warning("can't get peer addr!")
            
        pass
    
    def disconnect(self,peer_id,session):
        if session in self.sessions:
            if self.sessions[session][0]:
                try:
                    self.sessions[session][0].close()
                except:
                    pass

    def connectRemote_DL(self,peer_id,session):
        real_session = self.connect(peer_id,session)
        logging.debug("connect session %s %s"%(session,self.sessions))
        if real_session in self.sessions:
            return self.sessions[real_session][0]
        else:
            return None  

    def exchange(self,client_socket,remote_socket,session=None):
        self.count += 1
        while True:
            end = False
            try:
                socks = select.select([client_socket, remote_socket], [], [], 5)[0]
            except Exception as exp:
                logging.warning(exp.__str__())
                end = True
            else:
                for sock in socks:
                    try:
                        data = sock.recv(1024)
                    except Exception as exp:
                        logging.warning(exp.__str__())
                        end = True
                    else:
                        if not data:
                            continue
                        else:
                            try:
                                if sock is client_socket:
#                                     logging.debug("%d bytes from client %s" % (len(data),data[:20]))
                                    remote_socket.sendall(data)
                                else:
#                                     logging.debug( "%d bytes from server %s" % (len(data),data[:20]))
                                    client_socket.sendall(data)
                            except Exception as exp:
                                logging.warning(exp.__str__())
                                end = True
            if end:
                self.count -= 1
                try:
                    client_socket.close()
                except:
                    pass
                try:
                    remote_socket.close()
                except :
                    pass
                break   
             
    def addr_info(self,cmd = "addr_req"):
        ip = self.external_addr[0] if self.external_addr else self.station.ip
        port = self.external_addr[1] if self.external_addr else self.flow_port
        dictdata = {"command":cmd,
                    "parameters":{
                                  "ip":ip,
                                  "port":port,
                                  }}
        return self.DataMessage(dictdata = dictdata)


    def get_addr(self,peer_id):
        if peer_id in self.exchange_nodes and self.exchange_nodes[peer_id]:
#             logging.debug(self.exchange_nodes)
            return self.exchange_nodes[peer_id]
        self.exchange_nodes[peer_id] = None
        if not do_wait(func =lambda :  self.send_msg(peer_id, self.addr_info(cmd = "addr_req")),
                     test_func = lambda: self.exchange_nodes[peer_id],
                     times = 3):
#         self.send_msg(peer_id, self.addr_info(cmd = "addr_req"))
#         
#         try_count = 0
#         while not self.exchange_nodes[peer_id] and try_count<3:
#             time.sleep(1)
#             try_count += 1
#         if try_count==3:
# #             self.exchange_nodes.pop(peer_id)
            logging.warning("get %d address error %s "%(peer_id,self.exchange_nodes))
            return None
#         logging.debug(self.exchange_nodes)
        return  self.exchange_nodes[peer_id] 
    
    def process(self,ppmsg,addr):
        data_msg = self.DataMessage(bindata=ppmsg.get("app_data"))
        logging.debug("%d: receive from %s:%d   %s"%(self.station.node_id,addr[0],addr[1],data_msg.dict_data))
        command = data_msg.get("command")
        node_id = ppmsg.get("src_id")
        if command == "addr_req":
            self.send_msg(node_id, self.addr_info(cmd = "addr_res"))
        if command == "addr_res":
            self.exchange_nodes[node_id] = (data_msg.get_parameter("ip"),data_msg.get_parameter("port"))
#             self.connect(node_id)
        if command == "connect_req":
#             self.exchange_nodes[node_id] = (data_msg.get_parameter("ip"),data_msg.get_parameter("port"))
            self.connect(data_msg.get_parameter("node_id"),(data_msg.get_parameter("session_src"),
                                                              data_msg.get_parameter("session_dst"),
                                                              data_msg.get_parameter("session_id")),
                         isResponse = True)
                
        pass
    
    def run_command(self, command_string):
        cmd = command_string.split(" ")
        if cmd[0] in ["stat","set","flow"]:
            if cmd[0] =="stat":
                print("flow listen on port %d  (%d) %s"%(self.flow_port,
                                                    self.count,
                                                    self.external_addr if self.external_addr else "None"))
            if cmd[0] =="flow" and len(cmd)>=2 and cmd[1] =="self":
                self.get_self_addr()    
            if cmd[0] =="set" and len(cmd)>=4 and cmd[1] =="external":
                self.external_addr = (cmd[2],int(cmd[3]))   
            if cmd[0] =="flow" and len(cmd)>=2 and cmd[1] =="show":
                print("flow listen on port %d  (%d) %s"%(self.flow_port,
                                                    self.count,
                                                    self.external_addr if self.external_addr else "None"))
            if cmd[0] =="flow" and len(cmd)>=2 and cmd[1] =="detail":
                print(self.exchange_nodes,self.sessions)        
            if cmd[0] =="flow" and len(cmd)>=2 and cmd[1] =="reset":
                self.exchange_nodes = {}
                self.sessions ={}       
            if cmd[0] =="flow" and len(cmd)>=3 and cmd[1] =="arp":
                self.get_addr(int(cmd[2]))
            if cmd[0] =="flow" and len(cmd)>=3 and cmd[1] =="connect":
                session = self.connect(int(cmd[2]))
                if session and session in self.sessions:
                    print(session,self.sessions[session]) 
                else:
                    print("connect failure")                             
                               
            return True
        return False      
    

        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()