# coding=utf-8 
'''
Created on 2020年6月14日

@author: heguofeng


'''
import logging
import yaml
from _thread import start_new_thread

from ppnet.common import set_debug, parser_argument
from ppnet.ppl4node import PPDataNode


class Chat(object):
    def __init__(self, station, dest):
        self.quitting = False
        self.station = station
        self.dest = dest
        pass

    def send(self, text):
        self.station.send(text, self.dest)
        pass

    def receive(self):
        data, _ = self.station.receive(5)
        return data

    def run(self):
        start_new_thread(self.wait_receive, ())
        while not self.quitting:
            s = input(self.station.node_id.decode())
            if s == "quit":
                self.quit()
            else:
                self.send(s.encode())

    def wait_receive(self):
        while not self.quitting:
            data = self.receive()
            if data:
                print("\r{0}: {1} \n{2}>".format("there", data.decode(), self.station.underlayer.node_id.decode()))

    def quit(self):
        self.quitting = True


def main():
    options = parser_argument().parse_args()
    if options.config:
        config = yaml.load(open(options.config, "r"), Loader=yaml.FullLoader)
    else:
        config = {"node_id": b"PPSTA1",
                  "node_port": 54321, "DebugLevel": logging.DEBUG,
                  "auto_path": True,
                  "peers": ("127.0.0.1", 54320),
                  "nodes": {b"PPSTA1": {"node_id": b"PPSTA1", "ip": "127.0.0.1", "port": 54320, "nat_type": 7,
                                        "path": [b"PPSTA1"]},
                            b"PPSTA2": {"node_id": b"PPSTA2", "ip": "127.0.0.1", "port": 54321, "nat_type": 7,
                                        "path": [b"PPSTA2"]},
                            b"PPSTA3": {"node_id": b"PPSTA3", "ip": "127.0.0.1", "port": 54322, "nat_type": 7,
                                        "path": [b"PPSTA2", b"PPSTA3"]}}
                  # (id,ip,port,type)..]
                  }
    set_debug(config.get("DebugLevel", logging.WARNING),
              config.get("DebugFile", ""))

    print("Chatroom is lanching...")
    ppdatanode = PPDataNode(config)
    ppdatanode.start()

    chatroom = Chat(ppdatanode, tuple(config["peers"]))
    chatroom.run()

    print("Chatroom Quit!")


if __name__ == '__main__':
    main()

    pass
