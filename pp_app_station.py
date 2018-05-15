# coding=utf-8 
'''
Created on 2018年4月10日

@author: heguofeng
'''
import unittest
from pp_control import PPStation
from pp_flow import  DataLayer, Flow
import logging
from pp_link import set_debug
import yaml
import time
from pp_vpn import PPVPN
import optparse


class PPAppStation(PPStation):
    def __init__(self,config):
        super().__init__(config) 
        self.flow = Flow(station=self,data_port=config.get("data_port",7070))
        self.services.update({"flow":self.flow})
        
        if "services" in self.config:
            service_config = self.config["services"]
            if "vpn" in service_config:
                self.vpn = PPVPN(station = self,
                                 peer = self.config.get("vpn_peer",0),
                                 ip = self.config.get("vpn_ip",r"192.168.33.1"),
                                 mask = self.config.get("vpn_mask",r"255.255.255.0"),
                                 ) 
                self.services.update({"vpn":self.vpn})                
#                 
    def run_command(self, command_string):
        cmd = command_string.split(" ")
        run = False
        for service in self.services:
            run= True if self.services[service].run_command(command_string) else run
        run= True if super().run_command(command_string) else run
        if not run:
            print("not support command!")        
                 
#         PPStation.run_command(self, command_string)

def main(config):

    print("PPAppStation is lanching...")
    station = PPAppStation(config=config)
    station.start()
    try_count = 0
    while not station.status:
        time.sleep(2)
        station.status = station._check_status()
        try_count += 1
        if try_count > 10 or station.quitting:
            break
    print("node_id=%d online=%s" % (station.node_id, station.status))

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
            logging.exception("error in do command!")
        finally:
            pass
        if not station.quitting:
            s=input()

    print("PPAppStation Quit!")    

class Test(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass


    def testName(self):
        pass


if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option('--config', default='ppnetwork.yaml',dest='config_file', help='set config file')
    opt, args = parser.parse_args()
    if not (opt.config_file):
        parser.print_help()
    else:
        config = yaml.load(open(opt.config_file))
        set_debug(config.get("DebugLevel", logging.WARNING),
                    config.get("DebugFile", ""))
    #             config.get("DebugFile", ""),filter=lambda record: record.filename =="pp_flow.py" or record.filename =="pp_vpn.py")
        main(config=config)
    