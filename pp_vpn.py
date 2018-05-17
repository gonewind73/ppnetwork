# coding=utf-8
'''
Created on 2018年5月5日
@author: heguofeng
'''
import unittest
from pp_control import PPNetApp, PPStation
from pp_link import PP_APPID,set_debug, BroadCastId, wait_available, do_wait,\
   FakeNet, NAT_TYPE, ip_itos, ip_stoi
from tuntap import TunTap 
from _thread import start_new_thread
import logging
import socket
import sys
import time
from pp_flow import prepare_socket, Flow
import random
import hashlib
import struct
from collections import namedtuple


'''
vpn config:
    vlanid:  100
    iprange: 192.168.1.0-192.168.1.255  (turn to int)
    vlan_secret: b"12345678"
    
vpn function:
auth   vlan_token=mac(vlanid,node_id,secret,sequence)
auth_req(vlan_id,vlan_token,mynode_id,myip(optional))  broadcast on net,wait reply .
   node receive auth_req, 
       if self vlan:
            send auth_res , 
       elif public:
           broadcast to peers 
        
auth_res(vlan_id,vlan_token,status,available_ips(optional))
    if req given ip,check it is available to it,if ok , res ok to reqer,else res error to reqer
    if req has no ip, res min ip available to peer 
    vlan should has {ip:(node_id,last_active,type)} type is static 
    同时广播 arp_res(ip,node_id)  broadcast to vlan peer
    
arp
    arp_req(ip)   寻找ip对应的node_id,在vlan范围内broadcast 
        收到 req，如果在自己记录中，则发送arp_res(),不再则继续广播 
    arp_res(ip,node_id)   
        收到 res  记录对应信息，
        
switch
    分析报文中的目的IP。建立和目的IP的连接，发送数据。
    connect(ip)  建立连接,并监听数据
    send(ip,data) 如果没有建立连接，先connect(ip)

    和tuntap交换数据


'''
EXPIRE_TIME = 24*60*60*1000
IPInfo = namedtuple("IPInfo",['node_id',"sock","expire"])

class VPNBase(object):
    '''
    connect_peer should define by outside
    '''

    def __init__(self,ip,mask):
        self.ip = ip
        self.mask = mask
        self.tun = None
        self.quitting = True
        self.peer_sock = {}

    def start(self):
        self.quitting = False
        self.tun =  TunTap("Tun")

        if not self.tun:
            logging.warning("create tap device failure!")
            return None
        print("vpn start")
        self.tun.config(self.ip,self.mask)
        start_new_thread(self.listen, ())

    def quit(self):
        if self.quitting:
            return
        self.quitting = True
        for ip in self.peer_sock:
            self.peer_sock[ip].close()
        if self.tun:
            self.tun.close()
        logging.info("vpn quit!")

    def get_dst(self,data):
        return socket.inet_ntoa(data[16:20])
        
    def set_peersock(self,ip,peer_sock):
        self.peer_sock[ip] = peer_sock
        start_new_thread(self.receive_peer,(ip,peer_sock,))
        
    def connect(self,dst_ip):
        logging.warning("I don;t know how to connect!")
        return None

    def listen(self):
#         wait_count = 0
#         while not self.peer_sock and wait_count<10:
#             time.sleep(1)
#         if not self.peer_sock:
#             self.quit()

        while not self.quitting:
            try:
                data = self.tun.read()
                if data:
                    dst_ip = self.get_dst(data)
                    if dst_ip not in self.peer_sock:
                        sock = self.connect(dst_ip)
                        self.set_peersock(dst_ip,sock)
                    if dst_ip in self.peer_sock and self.peer_sock[dst_ip]:
                        self.peer_sock[dst_ip].sendall(data)
                        logging.debug("send %d %s"%(len(data),''.join('{:02x} '.format(x) for x in data)))

            except OSError as exps:
                logging.warning(exps)
                break
            except Exception as exp:
                logging.warning(exp)
                pass
        self.quit()

    def receive_peer(self,ip,peer_sock):
        while not self.quitting:
            try:
                data = peer_sock.recv(1024)
                # logging.debug("receive %s"%''.join('{:02x} '.format(x) for x in data))
                if data :
                    n= self.tun.write(data)
                    # logging.debug("write %d %d"%(n,len(data)))
                else:
                    continue
            except socket.timeout:
                continue
            except OSError as exps:
                self.peer_sock.pop(ip)
                logging.warning(exps)
                break
            except Exception as exp:
                logging.warning(exp)
                pass


class PPVPN(PPNetApp):
    '''
    vpn is a special proxy
    
    config = { 
            Vlan:100,
            IPRange: {start:100,end:200},
            VlanIP: 192.168.1.3
            VlanMask: 255.255.255.0,
            VlanSecret:12345678
    
    }
    '''
    class VPNMessage(PPNetApp.AppMessage):
        def __init__(self,**kwargs):
            tags_id={"auth_req":1,"auth_res":2,"arp_req":3,"arp_res":4,"connect_req":5,"connect_res":6,
                     "session_src":11,"session_dst":12,"session_id":13,"ip":14,"node_id":15,"token":16,"seed":17,"vlan_id":18}
            parameter_type = {
                              11:"I",12:"I",13:"I",14:"I",15:"I",17:"I",18:"I"}
            super().__init__( app_id=PP_APPID["VPN"],
                            tags_id=tags_id,
                            parameter_type=parameter_type,**kwargs)

    def __init__(self,station,config):
        
        super().__init__(station=station,app_id= PP_APPID["VPN"] )
        self.vlan_id = config.get("Vlan",0)
        ip_range = config.get("IPRange",{"start":"192.168.33.1","end":"192.168.33.255"})
        self.ip_range = {"start":ip_stoi(ip_range["start"]),"end":ip_stoi(ip_range["end"])}
        ip = config.get("VlanIP","0.0.0.0")
        self.ip = ip_stoi(ip)
        self.mask = config.get("VlanMask","255.255.255.0")
        self.secret = config.get("VlanSecret","12345678").encode()
#         self.peer = peer
        self.is_running = False
        self.vlan_table = {}  #{ip:(node_id,last_active)
        if self.ip:
            self._setNodeIp(self.station.node_id, self.ip)
        self.vpn = None
        self.testing = False
#         self.ip,self.mask = ip,mask
#         self.proxy_node = peer
#         self.proxy = None

    def start(self):
        super().start()
        start_new_thread(do_wait,(lambda :self.auth_req(BroadCastId),lambda: self.is_running==True,3))
        return self
    
    def quit(self):
        self.stop_vpn()
        super().quit()

    def start_vpn(self):
        ip = ip_itos(self.ip)
        logging.debug("start vpn with ip %s" %ip)
        if self.vpn:
            if not self.vpn.quitting:
                self.vpn.quit()
#         mask = socket.inet_ntoa(self.mask)
        self.vpn = VPNBase(ip,self.mask)
        self.vpn.connect = self._connect
        if not self.testing:
            self.vpn.start()
        self.is_running = True
#         self.station.flow.output_process =lambda sock,addr,session: self.proxy.set_peersock(sock)
#         self.proxy.connect_peer = lambda session_id: self.station.flow.connectRemote_DL(self.proxy_node,
#                                                             (self.station.node_id,self.proxy_node,session_id))
#         self.failure_count = 0
#         if self.proxy_node:
#             start_new_thread(self.waitProxyServer, ())


    def stop_vpn(self):
        if self.vpn:
            self.vpn.quit()
        self.is_running = False


#     def set_status(self,status=True):
#         if status:
#             session = self.station.flow.connect(peer_id=self.proxy_node)
#             logging.info("session %s %s",session,self.station.flow.sessions)
#             if session in self.station.flow.sessions and self.station.flow.sessions[session][0]:
#                 print("vpn ready to online")
#                 self.proxy.start()
#                 self.req_vpn(session)
#             else:
#                 print("can't connect vpn peer, offline!")
#         else:
#             if self.is_running:
#                 print("vpn offline")
#                 self.proxy.quit()
#                 self.is_running = False
                
    def _connect(self,sip):
        ip = ip_stoi(sip)
        if not (self.ip_range["start"] < ip < self.ip_range["end"]):
            logging.debug("not valid vlan ip")
            return 
        if ip not in self.vlan_table:
            node_id = self.wait_arp_req(ip)
        else:
            node_id = self.vlan_table[ip].node_id
        if node_id:
            session = self.station.flow.connect(peer_id=node_id)
            logging.info("session %s %s",session,self.station.flow.sessions)
            if session in self.station.flow.sessions and self.station.flow.sessions[session][0]:
                self.connect_req(session,self.ip)
                return self.station.flow.sessions[session][0]
            else:
                print("can't connect vpn peer, offline!")
        else:
            logging.warning("can't connect vpn peer")             

    def _getToken(self,node_id,seed):
        md5obj = hashlib.md5()
        md5obj.update(struct.pack("I",seed))
        md5obj.update(self.secret)
        md5obj.update(struct.pack("I",node_id))
        md5obj.update(struct.pack("I",self.vlan_id))
        return md5obj.digest()[:4]
    
    def _verify_msg(self,vpn_msg):
        if vpn_msg.get_parameter("vlan_id") == self.vlan_id:
            if vpn_msg.get_parameter("token") == self._getToken(vpn_msg.get_parameter("node_id"), 
                                                                vpn_msg.get_parameter("seed")):
                return True
            else:
                logging.warning("token mismatch %s"%self._getToken(vpn_msg.get_parameter("node_id"), 
                                                                vpn_msg.get_parameter("seed")))
        else:
            logging.debug("self vlan %d peer vlan %d"%(self.vlan_id,vpn_msg.get_parameter("vlan_id")))

        return False    

    def _getFreeIP(self):
        for ip in range(self.ip_range["start"],self.ip_range["end"]):
            if ip not in self.vlan_table:
                return ip
            if int(time.time()) > self.vlan_table[ip].expire:
                return ip 
        return 0
    
    def _verify_ip(self,node_id,ip):
        if ip in self.vlan_table:
            if self.vlan_table[ip].node_id== node_id:
                return ip
            elif int(time.time())  > self.vlan_table[ip].expire:
                return ip
            else:
                return self._getFreeIP()
        else:
            return ip
    
    def _castARP(self,vpn_msg):
        for ip in self.vlan_table:
            self.send_msg(self.vlan_table[ip].node_id, vpn_msg)
    
    def _cast(self,ppmsg):
        ppmsg.set("ttl",ppmsg.get("ttl")-1)
        for ip in self.vlan_table:
            self.station.send_ppmsg(self.station.peers[self.vlan_table[ip].node_id],ppmsg)

    def _setNodeIp(self,node_id,ip):
        for tip in list(self.vlan_table.keys()):
            ipinfo = self.vlan_table[tip]
            if ipinfo.node_id== node_id or int(time.time())>ipinfo.expire:
                self.vlan_table.pop(tip)
        self.vlan_table[ip] = IPInfo(node_id,None,int(time.time())+EXPIRE_TIME)                

    def _confirm(self,vpn_msg):
        ip = vpn_msg.get_parameter("ip")
        node_id = vpn_msg.get_parameter("node_id")
        if node_id == self.station.node_id:
            if ip:
                self.ip = ip
                logging.info("%d  set ip %d"%(self.station.node_id,self.ip))
                self.start_vpn()
            else:
                logging.warning("%d error set ip %d"%(self.station.node_id,self.ip))
        elif ip:
            result_ip = self._verify_ip(node_id, ip)
            if result_ip == ip:
                if ip in self.vlan_table and self.vlan_table[ip].node_id==node_id:
                    return
                self._setNodeIp(node_id,ip)
                self._castARP(vpn_msg)
            else:#error
                self.auth_res(node_id,result_ip)
        
    def auth_req(self,node_id):
        seed = random.randint(0,0xffffffff)
        dictdata = {"command":"auth_req",
                    "parameters":{
                        "node_id":self.station.node_id,
                        "token":self._getToken(self.station.node_id,seed),
                        "vlan_id":self.vlan_id,
                        "ip":self.ip,
                        "seed":seed}}
        logging.debug(dictdata)
        self.send_msg(node_id, PPVPN.VPNMessage(dictdata=dictdata))        

    def auth_res(self,node_id,ip):
        result_ip = 0
        if ip:
            result_ip = self._verify_ip(node_id, ip)
        else:
            #get max 
            result_ip = self._getFreeIP()
            pass
        seed = random.randint(0,0xffffffff)
        dictdata = {"command":"auth_res",
                    "parameters":{
                        "node_id":node_id,
                        "token":self._getToken(node_id,seed),
                        "vlan_id":self.vlan_id,
                        "ip":result_ip,
                        "seed":seed}}
        logging.debug("get ip %s"%result_ip)
        if result_ip:
            self._castARP(PPVPN.VPNMessage(dictdata=dictdata))
            self._setNodeIp(node_id,result_ip)
            self.arp_res(node_id, self.ip)            
#         self.send_msg(node_id, PPVPN.VPNMessage(dictdata=dictdata))

    def arp_req(self,ip):
        seed = random.randint(0,0xffffffff)
        dictdata = {"command":"arp_req",
                    "parameters":{
                        "node_id":self.station.node_id,
                        "token":self._getToken(self.station.node_id,seed),
                        "vlan_id":self.vlan_id,
                        "ip":ip,
                        "seed":seed}}
        self._castARP(PPVPN.VPNMessage(dictdata=dictdata)) 
           
    def arp_res(self,req_node_id,ip):
        seed = random.randint(0,0xffffffff)
        dictdata = {"command":"arp_res",
                    "parameters":{
                        "node_id":self.station.node_id,
                        "token":self._getToken(self.station.node_id,seed),
                        "vlan_id":self.vlan_id,
                        "ip":ip,
                        "seed":seed}}
        self.send_msg(req_node_id,PPVPN.VPNMessage(dictdata=dictdata))                
        
    def wait_arp_req(self,ip):
        self.arp_req(ip) 
        ipnode = wait_available(self.vlan_table,ip,3)
        if ipnode:
            return ipnode[0]
        else:
            return 0
               
    def connect_req(self,session,ip):
        dictdata = {"command":"connect_req",
                    "parameters":{
                      "session_src":session[0],
                      "session_dst":session[1],
                      "session_id":session[2],
                      "ip":ip}}
        logging.debug(dictdata)
        self.send_msg(session[1], PPVPN.VPNMessage(dictdata=dictdata))
        return

    def connect_res(self,session,ip):
        dictdata = {"command":"connect_res",
                    "parameters":{
                      "session_src":session[0],
                      "session_dst":session[1],
                      "session_id":session[2],
                      "ip":ip}}
        logging.debug(dictdata)
        self.send_msg(session[0], PPVPN.VPNMessage(dictdata=dictdata))
        return


        
    def process(self,ppmsg,addr):
        vpn_msg = PPVPN.VPNMessage(bindata=ppmsg.get("app_data"))
        logging.debug("%d: receive from %s:%d   %s"%(self.station.node_id,addr[0],addr[1],vpn_msg.dict_data))
        command = vpn_msg.get("command")
        
        node_id = ppmsg.get("src_id")
        if command == "auth_req":
            if self._verify_msg(vpn_msg):
                self.auth_res(node_id,vpn_msg.get_parameter("ip"))
        if command == "auth_res":
            if self._verify_msg(vpn_msg):
                self._confirm(vpn_msg)
        if command == "arp_req":
            if self._verify_msg(vpn_msg):
                if vpn_msg.get_parameter("ip") == self.ip:
                    self.arp_res(node_id,vpn_msg.get_parameter("ip"))
                else:
                    self._cast(ppmsg)
        if command == "arp_res":
            if self._verify_msg(vpn_msg):
                self._confirm(vpn_msg)     
        if command in ("connect_req","connect_res"):
            session = (vpn_msg.get_parameter("session_src"),vpn_msg.get_parameter("session_dst"),vpn_msg.get_parameter("session_id"))
            if not (session in self.station.flow.sessions and self.station.flow.sessions[session][0]):
                logging.warning("not connect , can't start vpn!")
                return
             
        if command == "connect_req":
            if session in self.station.flow.sessions and self.station.flow.sessions[session][0]:
                self.vpn.set_peersock(vpn_msg.get_parameter("ip"),self.station.flow.sessions[session][0])
                
            self.connect_res(session,self.ip)
        if command == "connect_res":
            if session in self.station.flow.sessions and self.station.flow.sessions[session][0]:
                self.vpn.set_peersock(vpn_msg.get_parameter("ip"),self.station.flow.sessions[session][0])
                
#             self.connect(node_id)


    def run_command(self, command_string):
        cmd = command_string.split(" ")
        if cmd[0] in ["stat","vpn"]:
            if cmd[0] =="stat":
                print("vpn %s ip: %s"%("is runing " if self.vpn and not self.vpn.quitting else "not run",
                                       ip_itos(self.ip)))
            if cmd[0] =="vpn" and len(cmd)>=3  and cmd[1]=="ip":
                print("vpn ip set to %s "%(cmd[1]))
                self.stop_vpn()
                self.ip = ip_stoi(cmd[2])
                self.start_vpn()
            if cmd[0] =="vpn" and len(cmd)>=3 and cmd[1]=="auth":
                self.auth_req(int(cmd[2]))
                time.sleep(1)
                self.run_command("vpn detail")
            if cmd[0] =="vpn" and len(cmd)>=3 and cmd[1]=="arp":
                self.arp_req(ip_stoi(cmd[2]))
                time.sleep(1)
                print(self.vlan_table) 
            if cmd[0] =="vpn" and len(cmd)>=2  and cmd[1]=="detail":
                print("vpn %d %s ip: %s"%(self.vlan_id, "is runing " if self.vpn and not self.vpn.quitting else "not run",
                                       ip_itos(self.ip)))                
                print(self.vlan_table)


            return True
        return False



    pass


class TestVPN(unittest.TestCase):
    
    inited = 0
    quiting = True
    
    def start(self):
        if self.inited == 1:
            return
        self.fake_net = FakeNet()


        self.nodes = {100: { "node_id": 100,"ip": "180.153.152.193", "port": 54330, "net_id":200,"secret": "",},
                 201: { "node_id": 201,"ip": "116.153.152.193", "port": 54330, "net_id":200,"secret": "",},
                 202:  { "node_id": 202,"ip": "116.153.152.193", "port": 54320, "net_id":200,"secret": "",}}
        config={"net_id":200, "node_port":54330,"nat_type":NAT_TYPE["Turnable"],"nodes":self.nodes,"ip":"0.0.0.0"}
        configA = config.copy()
        configA.update({"node_id":100, "node_ip":"118.153.152.193",})
        configB = config.copy()
        configB.update({"node_id":201, "node_ip":"116.153.152.193" })
        configC = config.copy()
        configC.update({"node_id":202, "node_ip":"116.153.152.193" ,"node_port":54320})
        self.stationA = PPStation(configA) 
        self.stationB = PPStation(configB)
        self.stationC = PPStation(configC)
        self.stationA.flow = Flow(station=self.stationA,data_port=7070)
        self.stationA.services.update({"flow":self.stationA.flow})
        self.stationB.flow = Flow(station=self.stationB,data_port=7071)
        self.stationB.services.update({"flow":self.stationB.flow})
        
        self.fake_net = FakeNet()
        self.fake_net.fake(self.stationA)
        self.fake_net.fake(self.stationB)
        self.fake_net.fake(self.stationC)    
#         self.stationA.beater.beat_interval = 0.1
#         self.stationB.beater.beat_interval = 0.1
#         self.stationB.beater.beat_interval = 0.1
        self.stationA.start()
        self.stationB.start()
        self.stationC.start()           
        
        self.vpnA = PPVPN(self.stationA,config={})   
        self.vpnB = PPVPN(self.stationB,config={})  
        self.vpnA.testing = True
        self.vpnA.ip = ip_stoi("192.168.33.10")
        self.vpnB.testing = True                              
        self.inited = 1
        
    def quit(self):
        if self.inited:
            self.stationA.quit()
            self.stationB.quit()
            self.stationC.quit()
            self.inited = 0   

    def setUp(self):
        set_debug(logging.DEBUG, "",
                debug_filter=lambda record: record.filename =="pp_vpn.py" or record.filename =="pp_flow.py"  ,
                  )
        self.start()
        pass


    def tearDown(self):
        self.quit()
        pass

    @unittest.skip("command only")
    def testAuth(self):
        self.vpnA.start()
        self.vpnB.start()
        time.sleep(3)
        self.vpnA.auth_req(BroadCastId)
        self.assertTrue(self.vpnA.is_running==True,"test Auth")
        pass
    
    @unittest.skip("command only")
    def testARP(self):
        self.vpnA.start()
        self.vpnB.start()
        time.sleep(1)
        self.vpnA.ip = ip_stoi("192.168.33.10")
#         self.vpnA.vlan_table[self.vpnB.ip]=()
#         self.vpnA.start_vpn()
        self.vpnB.ip = ip_stoi("192.168.33.12")
#         self.vpnB.start_vpn()
        self.vpnA.arp_req(self.vpnB.ip)
        print(self.vpnA.vlan_table)
        time.sleep(1)
        print(self.vpnA.vlan_table,self.vpnB.ip)        
        self.assertTrue(self.vpnA.vlan_table[self.vpnB.ip][0]==201,"test ARP")
        pass
    
    def testConnect(self):
        self.vpnA.start()
        self.vpnB.start()
        time.sleep(1)
        self.vpnA.ip = ip_stoi("192.168.33.10")
        self.vpnB.ip = ip_stoi("192.168.33.12")
        self.vpnA.arp_req(self.vpnB.ip)
        print(self.vpnA.vlan_table)
        time.sleep(1)
        print(self.vpnA.vlan_table,self.vpnB.ip)     
        self.vpnA._connect("192.168.33.12")   
        self.assertTrue(not self.vpnA.vpn.peer_sock[self.vpnB.ip]==None,"test connect")
        pass
    
    @unittest.skip("command only")
    def testVPNServer(self):
        vpn = VPNBase("192.168.33.10","255.255.255.0")
        sock = prepare_socket(timeout=10,port=7070)
        sock.listen(10)
        count = 0

        try: #active the port
            sock1 = prepare_socket(timeout=2,port=7070)
            sock1.connect(("100.100.100.100",6000))
        except Exception as exp:
            print(exp)
            pass
        finally:
            sock1.close()

        while count<10:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                count += 1
                continue
            else:
                print("accept from",conn.getpeername())
                vpn.start()
                vpn.set_peersock("192.168.33.12",conn)
                break

        input("any key to quit!")
        vpn.quit()
        pass

    @unittest.skip("command only")
    def testVPNClient(self):
        vpn = VPNBase("192.168.33.12","255.255.255.0")


        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server=input("server ip,default is 180.153.152.193:")
        if not len(server):
            server = "180.153.152.193"
        print(server)
        count = 0
        while count<10:
            try:
                sock.connect((server,7070))
#                 sock.connect(("180.153.152.193",7070))
            except socket.timeout:
                count += 1
                continue
            else:
                time.sleep(3)
                vpn.start()
                vpn.set_peersock("192.168.33.10",sock)
                break

        input("any key to quit!")
        vpn.quit()
        pass



if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    suite = unittest.TestSuite()
    if len(sys.argv) == 1:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestVPN)
    else:
        for test_name in sys.argv[1:]:
            print(test_name)
            suite.addTest(TestVPN(test_name))

    unittest.TextTestRunner(verbosity=2).run(suite)
