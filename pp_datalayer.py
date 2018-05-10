# coding=utf-8 
'''
Created on 2018年4月5日

@author: heguofeng
'''
import unittest
from pp_control import PPNetApp, FakeAppNet
from pp_tcp import Session, prepare_socket, Beater, PPStation
import socket
import logging
from _thread import start_new_thread
from pp_link import PP_APPID, set_debug, NAT_TYPE, BroadCastId
import struct
import time
import threading
import random
import select


'''define statics'''
SOCKS_VER5 = b'\x05'
METHOD_NO_AUTHENTICATION_REQUIRED = b'\x00'
METHOD_GSSAPI = b'\x01'
METHOD_USERNAME_PASSWORD = b'\x02'
METHOD_IANA_ASSIGNED_MIN = b'\x03'
METHOD_IANA_ASSIGNED_MAX = b'\x7F'
METHOD_RESERVED_FOR_PRIVATE_METHODS_MIN = b'\x80'
METHOD_RESERVED_FOR_PRIVATE_METHODS_MAX = b'\xFE'
METHOD_NO_ACCEPTABLE_METHODS = b'\xFF'
 
CMD_CONNECT = b'\x01'
CMD_BIND = b'\x02'
CMD_UDP = b'\x03'
 
RSV = b'\x00'
ATYP_IPV4 = 1
ATYP_DOMAINNAME = 3
ATYP_IPV6 = 4
 
REP_succeeded = b'\x00'
REP_general_SOCKS_server_failure = b'\x01'
REP_connection_not_allowed_by_ruleset = b'\x02'
REP_Network_unreachable = b'\x03'
REP_Host_unreachable = b'\x04'
REP_Connection_refused = b'\x05'
REP_TTL_expired = b'\x06'
REP_Command_not_supported = b'\x07'
REP_Address_type_not_supported = b'\x08'

class DataLayer(PPNetApp):
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
            tags_id={"addr_req":1,"addr_res":2,"connect_req":20,"connect_res":21,
                     "ip":3,"port":4,"peer_ip":5,"peer_port":6,"node_id":7,
                     "session_src":11,"session_dst":12,"session_id":13}
            parameter_type = {3:"str",4:"I",5:"str",6:"I",7:"I",
                              11:"I",12:"I",13:"I"}
            super().__init__( app_id=PP_APPID["Data"], 
                            tags_id=tags_id,
#                              tags_string=tags_string,
                            parameter_type=parameter_type,**kwargs)
                
    def __init__(self,station,data_port,session_limit=1000):
        '''
        [client_sock,remote_sock,failurecount,client_sock_type,remote_sock_type]
        sock_type  means terminal sock or exchange_sock. terminal sock no need ack
                        acked_sock or need_ack_sock
        '''
        super().__init__(station, app_id=PP_APPID["Data"], callback=None)
        self.sessions = {}  # {(src_id,dst_id,session_id):[client_sock,need-ack ,failurecount]}
        self.session_id = 0
        self.external_addr = None
        self.data_port = data_port
        self.local_addr = ("0.0.0.0",self.data_port)
        self.session_limit = session_limit
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
        self.servsock = prepare_socket(timeout=0,port=self.data_port)
        logging.info("datalayer: --> %s:%d -->" % ('0.0.0.0',self.data_port))        
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
            if not self.sessions[s_id][0] or not self.sessions[s_id][1]:
                self.sessions[s_id][2] += 1
                if self.sessions[s_id][2] > 2:
                    self.sessions.pop(s_id)
            else:
                self.sessions.pop(s_id)
                
        if not self.send_in_minute:
            self.beat_null()
                        
        if not self.quitting:
            self.send_in_minute = False
            
            self.timer = threading.Timer(60, self.check)
            self.timer.start()
               
    def beat_null(self):
        '''
        just keep nat firewall know it is runing
        '''
        logging.debug("datalayer beat null")
        try:
            sock = prepare_socket(timeout=1,port=self.data_port)
            sock.connect((socket.inet_ntoa(struct.pack('I', socket.htonl(random.randint(1677721600, 1694498816)))),
                                random.randint(10000, 60000)))
        except socket.timeout:
            pass
        except:
            logging.exception("beat null error")
            pass   

    def get_self_addr(self):
        temp_config = self.station.config.copy()
        temp_config.update({"node_port":self.data_port,"node_id":BroadCastId-1})
        temp_station=PPStation(config = temp_config)
        temp_station.start()
        try_count = 0
        while not temp_station.status and try_count<10:
            time.sleep(1)
            try_count += 1
        if temp_station.status:
            self.external_addr = (temp_station.ip,temp_station.port)
            self.local_addr = temp_station.local_addr
            logging.info("get self external_addr %s:%d"%self.external_addr)
            temp_station.quit()
        else:
            temp_station.quit()
            if self.station.status and self.station.nat_type==NAT_TYPE["Turnable"]:
                self.external_addr = (self.station.ip,self.data_port)
                self.local_addr = (self.station.local_addr[0],self.data_port)
                logging.info("get self external_addr %s:%d by guess"%self.external_addr)
            else:
                logging.error("can't get external address,quit")                
#                 self.quit()
#                 self.station.quit()
            return                      

    def listen(self,):
        while not self.quitting:
            try:
                client_sock, client_addr = self.servsock.accept()
            except Exception as exp:
                logging.warning(exp)
                pass
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
            data =  Beater.BeatMessageV2.packip(peer_addr[0])
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
            info = {"ip":Beater.BeatMessageV2.unpackip(data[0:4]),
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
                if session[1]==self.station.node_id:
                    if session not in self.sessions:
                        self.sessions[session]=[client_sock,need_ack,0]
                    if need_ack:
                        self.send_peer_info(client_sock, session)
                    if self.output_process :                            
                        start_new_thread(self.output_process,(client_sock,client_addr,session))
                else:
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
                #discard
#         else:
#             logging.debug("unknown peer")

# 
#     def output_process(self,client_sock,client_addr,session):
#         '''
#         canbe overload 
#         '''
#         pass     

    def req_connect(self,peer_id,dst_id,session):
        dictdata = {"command":"connect_req",
                    "parameters":{
#                       "ip":addr[0],
                      "node_id":dst_id,
                      "session_src":session[0],
                      "session_dst":session[1],
                      "session_id":session[2]}}
        logging.debug(dictdata)
        self.send_msg(peer_id, DataLayer.DataMessage(dictdata=dictdata))
        
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
                        self.session_process(sock, self.exchange_nodes[peer_id],need_ack=not isResponse)
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
    
#     def get_external_addr(self):
#         if self.external_addr:
#             return self.external_addr
#         for peer_id in self.exchange_nodes:
#             logging.debug(self.exchange_nodes)
#             result = self.try_connect(peer_id,(self.station.ip,self.data_port),self.exchange_nodes[peer_id])
#             if result:
#                 print("get external_addr %s"%result)
#                 self.external_addr = (result["ip"],result["port"])
#                 break
#         return self.external_addr
#                 
#     def try_connect(self,peer_id,self_addr,peer_addr):
#         self.req_connect(peer_id, self.station.node_id, session=(self.station.node_id,peer_id,999999))
#         info = None
# #         sock = prepare_socket(timeout=3,port=self.data_port)
#         sock = prepare_socket(timeout=3)
#         try:
#             sock.connect(peer_addr)        
#             self.send_peer_info(sock, (self.station.node_id,peer_id,999999))
#             info = self.get_peer_info(sock)
#         except Exception as exp:
#             logging.exception("try connect error %s %s"%(exp,"%s:%d"%peer_addr if peer_addr else "None"))
#         logging.info(info)
#         return info
   
    def connectRemote_DL(self,peer_id,session):
        real_session = self.connect(peer_id,session)
        logging.debug("connect session %s %s"%(session,self.sessions))
        if real_session in self.sessions:
            return self.sessions[real_session][0]
        else:
            return None  

    def exchange(self,client_socket,remote_socket):
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
                try:
                    self.count -= 1
                    client_socket.close()
                    remote_socket.close()
                except Exception as exp:
                    logging.warning(exp.__str__())
                    pass
                break   
             
    def addr_info(self,cmd = "addr_req"):
        ip = self.external_addr[0] if self.external_addr else self.station.ip
        port = self.external_addr[1] if self.external_addr else self.data_port
        dictdata = {"command":cmd,
                    "parameters":{
                                  "ip":ip,
                                  "port":port,
                                  }}
        return self.DataMessage(dictdata = dictdata)
#         self.connect_port = random.randint(10000, 60000)
#         proxy_socket = prepare_socket(timeout=5,port=port)
#         try:
#             proxy_socket.connect((self.station.peers[self.proxy_node].ip,self.station.peers[self.proxy_node].port))
#         except:
#             pass

    def get_addr(self,peer_id):
        if peer_id in self.exchange_nodes and self.exchange_nodes[peer_id]:
#             logging.debug(self.exchange_nodes)
            return self.exchange_nodes[peer_id]
        self.exchange_nodes[peer_id] = None
        self.send_msg(peer_id, self.addr_info(cmd = "addr_req"))
        try_count = 0
        while not self.exchange_nodes[peer_id] and try_count<3:
            time.sleep(1)
            try_count += 1
        if try_count==3:
#             self.exchange_nodes.pop(peer_id)
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
#                 sock = self.proxy.connectRemote((data_msg.get_parameter("ip"),data_msg.get_parameter("port")))
#                 if sock:
#                     sock.sendall(struct.pack("I",data_msg.get_parameter("session_id")))
                
        pass
    
    def run_command(self, command_string):
        cmd = command_string.split(" ")
        if cmd[0] in ["stat","try","set","datalayer"]:
            if cmd[0] =="stat":
                print("datalayer listen on port %d  (%d) %s"%(self.data_port,
                                                    self.count,
                                                    self.external_addr if self.external_addr else "None"))
            if cmd[0] =="try" and len(cmd)>=1:
                self.get_self_addr()    
            if cmd[0] =="set" and len(cmd)>=4 and cmd[1] =="external":
                self.external_addr = (cmd[2],int(cmd[3]))   
            if cmd[0] =="datalayer" and len(cmd)>=2 and cmd[1] =="show":
                print("datalayer listen on port %d  (%d) %s"%(self.data_port,
                                                    self.count,
                                                    self.external_addr if self.external_addr else "None"))
            if cmd[0] =="datalayer" and len(cmd)>=2 and cmd[1] =="detail":
                print(self.exchange_nodes,self.sessions)        
            if cmd[0] =="datalayer" and len(cmd)>=2 and cmd[1] =="reset":
                self.exchange_nodes = {}
                self.sessions ={}       
            if cmd[0] =="datalayer" and len(cmd)>=3 and cmd[1] =="connect":
                session = self.connect(int(cmd[2]))
                if session:
                    print(session,self.sessions[session]) 
                else:
                    print("connect failure")                             
                               
            return True
        return False      
           
class ProxyBase(object):        
    def __init__(self,port=7070):
        self.port = port
        self.quitting = False
        self.timer = None
        self.servsock = None
        self.count = 0  #session count
        self.sessions = {}  # {session_id:[client_sock,remote_sock,failurecount]
        self.session_id = 0

    def start(self):
        self.quitting = False
        self.count = 0
        self.servsock = prepare_socket(timeout=0,port=self.port)
        logging.info("proxy: --> %s:%d -->" % ('0.0.0.0',self.port))        
        self.servsock.listen(1000)
        start_new_thread(self.listen, ())
        start_new_thread(self.beat_null, ())

    def proxy_start(self):
        self.quitting = False
        self.count = 0
        self.servsock = prepare_socket(timeout=0,port=self.port)
        logging.info("proxy: --> %s:%d -->" % ('0.0.0.0',self.port))        
        self.servsock.listen(1000)
        start_new_thread(self.listen, ())
 

    def quit(self):
        self.quitting = True
        if self.timer:
            self.timer.cancel()
            self.timer = None
        if self.servsock:
            self.servsock.close()
            self.servsock = None            

    def listen(self,):
        while not self.quitting:
            try:
                client_sock, client_addr = self.servsock.accept()
            except Exception as exp:
                logging.warning(exp)
                pass
            else:
                start_new_thread(self.proxy_receive,(client_sock,client_addr))   

        
    def beat_null(self):
        '''
        just keep nat firewall know it is runing
        '''
        logging.debug("proxy server beat null")
        try:
            sock = prepare_socket(timeout=10,port=self.port)
            sock.connect((socket.inet_ntoa(struct.pack('I', socket.htonl(random.randint(1677721600, 1694498816)))),
                                random.randint(10000, 60000)))
        except Exception as exp:
#             logging.warning("error in beat null %s: %s "%(sock,exp.__str__()))
            pass
        
        for s_id in list(self.sessions.keys()):
            if not self.sessions[s_id][0] or  not self.sessions[s_id][1]:
                self.sessions[s_id][2] += 1
                if self.sessions[s_id][2] > 2:
                    self.sessions.pop(s_id)
            else:
                self.sessions.pop(s_id)
                
        if not self.quitting:
            self.timer = threading.Timer(60, self.beat_null)
            self.timer.start()        

    def connectRemote(self,addr):
        remote_socket = prepare_socket(timeout = 5)
        try:
            remote_socket.connect(addr)
            remote_socket.settimeout(0)
            return remote_socket
        except socket.timeout:
            pass
        except Exception as exp:
            logging.warning("connect %s error %s"%(addr,exp.__str__()))
            return None        
        
    def proxy(self,client_socket,remote_socket):
        self.count += 1
        while True:
            end = False
            try:
                socks = select.select([client_socket, remote_socket], [], [], 3)[0]
            except Exception as exp:
                logging.warning(exp.__str__())
                end = True
            else:
                for sock in socks:
                    try:
                        data = sock.recv(1024)
#                         logging.debug("receive data:"%data)
                    except Exception as exp:
                        logging.warning(exp.__str__())
                        end = True
                    else:
                        if not data:
                            continue
                        else:
                            try:
                                if sock is client_socket:
                                    logging.debug("%d bytes from client %s" % (len(data),data[:20]))
                                    remote_socket.sendall(data)
                                else:
                                    logging.debug( "%d bytes from server %s" % (len(data),data[:20]))
                                    client_socket.sendall(data)
                            except Exception as exp:
                                logging.warning(exp.__str__())
                                end = True
            if end:
                try:
                    self.count -= 1
                    client_socket.close()
                    remote_socket.close()
                except Exception as exp:
                    logging.warning(exp.__str__())
                    pass
                break
           
class ProxyClient(ProxyBase):
    '''
    use tcp mode
    listen on port
    send2Server(data) 
    
    '''
    def __init__(self,proxy_addr=None,port=7070,connectProxy=None):
        super().__init__(port)
        self.setProxy(proxy_addr)
        if connectProxy:
            self.connectProxy = connectProxy

    def setProxy(self,proxy_addr=None):
        self.proxy_addr = proxy_addr
        return self.proxy_addr
        
    def connectProxy(self,session_id):
        return super().connectRemote(self.proxy_addr)
        
    def proxy_receive(self,client_sock,client_addr):
        logging.debug("%s %s"%(client_sock,client_addr))
        self.session_id += 1
        self.sessions[self.session_id] = [client_sock,None,0]
        remote_socket = self.connectProxy(self.session_id)
        if remote_socket:
            start_new_thread(self.proxy,(self.sessions[self.session_id][0],remote_socket))

                        

class ProxyServer(ProxyBase):    
    '''
    wait on port accept proxy client connect

    '''
    def __init__(self,send2Peer=None,port=7070):
        self.quitting = False
        self.send2Peer= send2Peer
        self.port = port
        self.sessions = {}   #{(node_id,session_id):[stage,socket,session]}
        self.timer = None
        self.count = 0
        

    def listen(self,):
        while not self.quitting:
            client_sock, client_addr = self.servsock.accept()
            start_new_thread(self.proxy_receive,(client_sock,client_addr))    
         

    def proxy_receive(self,client_sock,client_addr):
        try:
            data = client_sock.recv(7)
            if data:
                logging.debug(" proxy server receive data:(%d) %s "%(len(data),data[:20]))
#         except socket.timeout:
        except:
            return 
        if data[:7]==b"CONNECT":
            self.init_http(client_sock, data)
        else:
            self.init_sock5(client_sock, data)
        

    def init_sock5(self,client_sock,data):
        if len(data)>2:
            socks_version = data[0]
            if not socks_version == 5:
                logging.warning("discard error message %s"%data[:20])
                return
            method_number = data[1]
            methods_client_supported = data[2:2+method_number]
            logging.debug("client support method %s"%methods_client_supported)
            client_sock.sendall(SOCKS_VER5+METHOD_NO_AUTHENTICATION_REQUIRED)
            
            data = client_sock.recv(4)
            socks_version,command,rsv,address_type = data[:4]
            logging.debug("version %s command %s address_type %s"%(socks_version,command,address_type))
            address = data[3:4]
            if address_type == ATYP_DOMAINNAME:
                address += client_sock.recv(1)
                domain_length = address[1]
                address += client_sock.recv(domain_length+2)
                domain = address[2:2+domain_length]
                port = address[2+domain_length:]
                hostname = domain.decode()
            elif address_type == ATYP_IPV4:
                domain_length = 0
                address += client_sock.recv(6)
                domain = address[1:5]
                hostname = '%s.%s.%s.%s' % (str(domain[0]), str(domain[1]), str(domain[2]), str(domain[3]))
                port = address[5:7]
            else:
                return False
            logging.debug("address %s hostname %s port %s"%(address,hostname,port))
            nport = struct.unpack(">H",port)[0]
                
            remote_socket = self.connectRemote(addr=(hostname, nport))
            if remote_socket:
                logging.info("connect remote %s:%d success. "%(hostname, nport))
                reply = SOCKS_VER5 + REP_succeeded +RSV + address
                client_sock.sendall(reply)
                start_new_thread(self.proxy, (client_sock,remote_socket))
            else:
                reply = SOCKS_VER5 + REP_Network_unreachable
                client_sock.sendall(reply)
        pass
                
    def init_http(self,client_sock,data):
        data1 = client_sock.recv(1024)
        data += data1
        logging.debug("receive data %s"%data[:20])
        parts = data.decode().split(" ")
        if parts[0]=="CONNECT":
            host_port = parts[1].split(":")
            logging.debug("receive connect to %s"%host_port)
        else:
            logging.warning(parts)
            return
            
        remote_socket = self.connectRemote(addr=(host_port[0], int(host_port[1])))
        if remote_socket:
            logging.info("connect remote %s:%d success. set stage 1 socket %s"%(host_port[0], int(host_port[1]),remote_socket) )
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")           
            start_new_thread(self.proxy, (client_sock,remote_socket))


class PPProxy(PPNetApp):
    def __init__(self,station,proxy_node,data_port=7070,proxy_port=6000):
        super().__init__(station=station,app_id= PP_APPID["Proxy"] )
        self.proxy_node = proxy_node
        self.proxy_port = proxy_port
        self.is_running = False
        self.proxy = None
        
    def start(self):
        super().start()
        self.start_proxy()
        return self
            
    def start_proxy(self):
        if self.proxy_node == self.station.node_id:
            self.proxy = ProxyServer(port=self.proxy_port)
            self.is_proxy_server = True
        else:
            self.proxy = ProxyClient(port=self.proxy_port)
            self.is_proxy_server = False
        self.proxy.start = self.proxy.proxy_start            
        if self.is_proxy_server:
            self.station.datalayer.output_process = lambda x,y,z: self.proxy.proxy_receive(x,y)
            self.proxy.start()
            self.is_running  = True             
        else:
#             self.input_process = self.proxy_client
            self.is_running  = False 
            self.failure_count = 0
            self.proxy.connectProxy = lambda session_id: self.station.datalayer.connectRemote_DL(self.proxy_node,
                                                            (self.station.node_id,self.proxy_node,session_id))
            start_new_thread(self.waitProxyServer, ())        
            
    def stop_proxy(self):
        if self.proxy:
            self.proxy.quit()
        self.is_running = False

#     def connectRemote_DL(self,peer_id,session_node,session_id):
#         session = self.station.datalayer.connect(peer_id,session_node,session_id)
#         logging.debug("connect session %s %s"%(session,self.station.datalayer.sessions))
#         if session in self.station.datalayer.sessions:
#             return self.station.datalayer.sessions[session][0]
#         else:
#             return None

    def waitProxyServer(self):
        if self.proxy_node in self.station.peers and self.station.peers[self.proxy_node].status:
            if not self.is_running :
                self.failure_count += 1
                self.set_status(True)
        else:
            self.set_status(False)
        if not self.station.quitting: 
            if self.failure_count<3:
                self.timer = threading.Timer(1, self.waitProxyServer)
                self.timer.start()
            else:
                print("connect to proxy server %d failure!!!"%self.proxy_node)        

            
    def set_status(self,status=True):
        if status:
            session = self.station.datalayer.connect(peer_id=self.proxy_node)
            logging.info("session %s %s",session,self.station.datalayer.sessions)
            if session in self.station.datalayer.sessions and self.station.datalayer.sessions[session][0]:
                print("proxy server online,start to proxy")
                self.proxy.start()
                self.is_running = True
            else:
                print("can't connect server, offline!")
        else:
            if self.is_running:
                print("proxy server offline,stop proxy")
                self.proxy.quit()
                self.is_running = False            


    def run_command(self, command_string):
        cmd = command_string.split(" ")
        if cmd[0] in ["stat","proxy"]:
            if cmd[0] =="stat":
                print("proxy server %d  self listen on port %d %s"%(self.proxy_node,self.proxy_port,
                                                    "is runing " if self.is_running else "not run"))
            if cmd[0] =="proxy" and len(cmd)>=2:
                print("proxy node set to :%d "%(int(cmd[1]))) 
                self.stop_proxy()
                self.proxy_node =  int(cmd[1])
                self.start_proxy()

                               
            return True
        return False        


class Test(unittest.TestCase):


    def setUp(self):
        set_debug(logging.DEBUG, "")
        self.stationA = FakeAppNet(node_id=100)
        self.stationB = FakeAppNet(node_id=200)
        
        processes = {100:self.client.process,
                     200:self.server.process}
        self.stationA.set_process(processes)
        self.stationB.set_process(processes)           
        pass


    def tearDown(self):

        pass
    def testSession(self):
        receive_buffer = ""
        send_buffer = ""
        def receive_process(session,data):
            nonlocal receive_buffer
            receive_buffer += data
        def send_process(session,data):
#             nonlocal send_buffer
#             send_buffer += data
            print(session,data)
            
        s = Session(send_process=send_process,
                          receive_process=receive_process)
        for i in range(10):
            session={"id":100,"size":0,"start":i,"end":i+1}
            print(s.send(session,str(i)))
            rsession={"id":100,"size":0,"start":9-i,"end":9-i+1}
            print(s.receive(rsession, str(9-i)))
        session={"id":100,"size":10,"start":10,"end":10}
        print(s.send(session, "end"))
        print(s.receive(session, "end"))
        print(send_buffer,receive_buffer)
        self.assertEqual(receive_buffer, "0123456789", "test session")
        self.assertEqual(s.receive_size, 10, "test session")
        self.assertEqual(s.send_size, 10, "test session")



    def TtestSock5(self):
        self.client.start()
        self.server.start()
        time.sleep(1)
        input(prompt="anykey to quit")
        self.client.quit()
        self.server.quit()
        pass

    def TtestProxy(self):
        client = ProxyClient(proxy_addr=("127.0.0.1",7070),send2Peer = None, port = 443)
        server = ProxyServer(port=7070,send2Peer= None)
        server.start()
        client.start()
        s=input()
        server.quit()
        client.quit()
        
    def testDataLayer(self):
        self.client = DataLayer(self.stationA,data_port=7200)
        self.server = DataLayer(self.stationB,data_port=7300)
        processes = {100:self.client.process,
                     200:self.server.process}
        self.stationA.set_process(processes)
        self.stationB.set_process(processes)          
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()