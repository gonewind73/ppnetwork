# coding=utf-8
'''
Created on 2018年5月5日
@author: heguofeng
'''
import unittest
from pp_control import PPNetApp
from pp_link import PP_APPID,set_debug
from tuntap import WinTap,Tap,TunTap 
import threading
from _thread import start_new_thread
import logging
import select
import socket
import sys
import time



class VPNBase(object):
    '''
    connect_peer should define by outside
    '''

    def __init__(self,ip,mask):
        self.ip = ip
        self.mask = mask
        self.tun = None
        self.quitting = False
        self.peer_sock = None

    def start(self):
        self.quitting = False
        self.tun =  TunTap("Tun")

        if not self.tun:
            logging.warning("create tap device failure!")
            return None
        print("start config")
        self.tun.config(self.ip,self.mask)
        start_new_thread(self.listen, ())

    def quit(self):
        if self.quitting:
            return
        self.quitting = True
        if self.peer_sock:
            self.peer_sock.close()
        if self.tun:
            self.tun.close()
        logging.info("vpn quit!")

    def set_peersock(self,peer_sock):
        self.peer_sock = peer_sock
        start_new_thread(self.receive_peer,())
        logging.info("vpn start!")

    def listen(self):
        wait_count = 0
        while not self.peer_sock and wait_count<10:
            time.sleep(1)
        if not self.peer_sock:
            self.quit()

        while not self.quitting:
            try:
                data = self.tun.read()
                if data:
                    self.peer_sock.sendall(data)
                    logging.debug("send %d %s"%(len(data),''.join('{:02x} '.format(x) for x in data)))

            except OSError as exps:
                logging.warning(exps)
                break
            except Exception as exp:
                logging.warning(exp)
                pass
        self.quit()

    def receive_peer(self):
        while not self.quitting and self.peer_sock:
            try:
                data = self.peer_sock.recv(1024)
                # logging.debug("receive %s"%''.join('{:02x} '.format(x) for x in data))
                if data :
                    n= self.tun.write(data)
                    # logging.debug("write %d %d"%(n,len(data)))
                else:
                    continue
            except socket.timeout:
                continue
            except OSError as exps:
                print(exps)
                break
            except Exception as exp:
                logging.warning(exp)
                pass
        self.quit()

class PPVPN(PPNetApp):
    '''
    vpn is a special proxy
    '''
    class VPNMessage(PPNetApp.AppMessage):
        def __init__(self,**kwargs):
            tags_id={"vpn_req":1,"vpn_res":2,
                     "session_src":11,"session_dst":12,"session_id":13}
            parameter_type = {
                              11:"I",12:"I",13:"I"}
            super().__init__( app_id=PP_APPID["VPN"],
                            tags_id=tags_id,
                            parameter_type=parameter_type,**kwargs)

    def __init__(self,station,peer,ip,mask):
        super().__init__(station=station,app_id= PP_APPID["VPN"] )
        self.peer = peer
        self.is_running = False
        self.ip,self.mask = ip,mask
        self.proxy_node = peer
        self.proxy = None

    def start(self):
        super().start()
        self.start_proxy()
        return self

    def start_proxy(self):
        self.proxy = VPNBase(self.ip,self.mask)
#         self.station.datalayer.output_process =lambda sock,addr,session: self.proxy.set_peersock(sock)
#         self.proxy.connect_peer = lambda session_id: self.station.datalayer.connectRemote_DL(self.proxy_node,
#                                                             (self.station.node_id,self.proxy_node,session_id))
        self.failure_count = 0
        if self.proxy_node:
            start_new_thread(self.waitProxyServer, ())


    def stop_proxy(self):
        if self.proxy:
            self.proxy.quit()
        self.is_running = False


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
                print("connect to vpn peer %d failure!!!"%self.proxy_node)


    def set_status(self,status=True):
        if status:
            session = self.station.datalayer.connect(peer_id=self.proxy_node)
            logging.info("session %s %s",session,self.station.datalayer.sessions)
            if session in self.station.datalayer.sessions and self.station.datalayer.sessions[session][0]:
                print("vpn ready to online")
                self.proxy.start()
                self.req_vpn(session)
            else:
                print("can't connect vpn peer, offline!")
        else:
            if self.is_running:
                print("vpn offline")
                self.proxy.quit()
                self.is_running = False

    def req_vpn(self,session):
        dictdata = {"command":"vpn_req",
                    "parameters":{
                      "session_src":session[0],
                      "session_dst":session[1],
                      "session_id":session[2]}}
        logging.debug(dictdata)
        self.send_msg(session[1], PPVPN.VPNMessage(dictdata=dictdata))
        return

    def res_vpn(self,session):
        dictdata = {"command":"vpn_res",
                    "parameters":{
                      "session_src":session[0],
                      "session_dst":session[1],
                      "session_id":session[2]}}
        logging.debug(dictdata)
        self.send_msg(session[0], PPVPN.VPNMessage(dictdata=dictdata))
        return

    def process(self,ppmsg,addr):
        vpn_msg = PPVPN.VPNMessage(bindata=ppmsg.get("app_data"))
        logging.debug("%d: receive from %s:%d   %s"%(self.station.node_id,addr[0],addr[1],vpn_msg.dict_data))
        command = vpn_msg.get("command")
        session = (vpn_msg.get_parameter("session_src"),vpn_msg.get_parameter("session_dst"),vpn_msg.get_parameter("session_id"))
        if not (session in self.station.datalayer.sessions and self.station.datalayer.sessions[session][0]):
            logging.warning("not connect , can't start vpn!")
            return
        node_id = ppmsg.get("src_id")
        if command == "vpn_req":
            self.proxy_node = node_id
            self.proxy.start()
            if session in self.station.datalayer.sessions and self.station.datalayer.sessions[session][0]:
                self.proxy.set_peersock(self.station.datalayer.sessions[session][0])
                self.is_running = True
            self.res_vpn(session)
        if command == "vpn_res":
            if session in self.station.datalayer.sessions and self.station.datalayer.sessions[session][0]:
                self.proxy.set_peersock(self.station.datalayer.sessions[session][0])
                self.is_running = True
#             self.connect(node_id)


    def run_command(self, command_string):
        cmd = command_string.split(" ")
        if cmd[0] in ["stat","vpn"]:
            if cmd[0] =="stat":
                print("vpn %d %s"%(self.proxy_node,
                                   "is runing " if self.proxy and not self.proxy.quitting else "not run"))
            if cmd[0] =="vpn" and len(cmd)>=2:
                print("vpn node set to :%d "%(int(cmd[1])))
                self.stop_proxy()
                self.proxy_node =  int(cmd[1])
                self.start_proxy()


            return True
        return False



    pass


class Test(unittest.TestCase):


    def setUp(self):
        set_debug(logging.DEBUG, "")
        pass


    def tearDown(self):
        pass


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
                vpn.set_peersock(conn)
                break

        input("any key to quit!")
        vpn.quit()
        pass

    def testVPNClient(self):
        vpn = VPNBase("192.168.33.12","255.255.255.0")


        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        count = 0
        while count<10:
            try:
                sock.connect(("180.153.152.193",7070))
#                 sock.connect(("180.153.152.193",7070))
            except socket.timeout:
                count += 1
                continue
            else:
                time.sleep(3)
                vpn.start()
                vpn.set_peersock(sock)
                break

        input("any key to quit!")
        vpn.quit()
        pass



if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    suite = unittest.TestSuite()
    if len(sys.argv) == 1:
        suite = unittest.TestLoader().loadTestsFromTestCase(Test)
    else:
        for test_name in sys.argv[1:]:
            print(test_name)
            suite.addTest(Test(test_name))

    unittest.TextTestRunner(verbosity=2).run(suite)
