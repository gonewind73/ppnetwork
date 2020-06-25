# coding=utf-8
"""
Created on 2018年2月28日

@author: heguofeng


"""
import logging
import socket


class PPLayer(object):
    """
    传输层模型
    send,receive 都调用underlayer.send,receive.
    """

    def __init__(self, underlayer=None):
        self._underlayer = underlayer
        self._callback = None
        self.services = dict()

    def __del__(self):
        if self._underlayer:
            self._underlayer.quit()

    def start(self):
        if self._underlayer:
            self._underlayer.start()
        return self

    def quit(self):
        return

    def send(self, data, addr):
        """
        自定义处理过程，调用下层服务
        :param data:
        :param addr:
        :return:
        """
        return self._underlayer.send(data, addr)

    def receive(self, count=1522):
        """
        自定义处理过程，调用下层服务
        :param timeout:
        :return:
        """
        data, addr = self._underlayer.receive(count)
        # add self process
        return data, addr

    @property
    def underlayer(self):
        return self._underlayer

    @underlayer.setter
    def underlayer(self, layer):
        self._underlayer = layer

    @property
    def callback(self):
        return self._callback

    @callback.setter
    def callback(self, callback_fun):
        self._callback = callback_fun

    def set_callback(self, callbackfunc):
        self.callback = callbackfunc

    def process(self, data, addr):
        if self._callback:
            self._callback(data, addr)
        else:
            logging.warning("{0}: should define layer process!".format(self._underlayer))
        pass

    def add_service(self, app):
        self.services.update({app.get_app_id(): app})
        app.set_station(self)
        pass

    def remove_service(self, app_id):
        self.services.pop(app_id, None)

    def set_underlayer(self, layer):
        self.underlayer = layer
        pass

    def run_command(self, command_string):
        return ""


class PPL1Node(PPLayer):
    def __init__(self, local_addr=None):
        super().__init__()
        self.local_addr = local_addr
        self._sock = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.local_addr and self.local_addr[1]:
            self._sock.bind(self.local_addr)
            logging.info(" Socket bind to {0}".format(self.local_addr))

    def send(self, data, dst):
        try:
            self._sock.sendto(data, dst)
            logging.debug(
                "send to %s:%d\n %s ......" % (dst[0], dst[1], ''.join('{:02x} '.format(x) for x in data[:16])))
        except OSError as error:
            logging.debug("%s ip:%s port %d" % (error, dst[0], dst[1]))

    def receive(self, count=1522):
        try:
            data, addr = self._sock.recvfrom(count)
            logging.debug(
                "receive from %s:%d\n %s ...... " % (addr[0], addr[1], ''.join('{:02x} '.format(x) for x in data[:20])))
            return data, addr
        except (socket.timeout, OSError) as exps:
            logging.debug(exps)
            return None, None

    @property
    def sock(self):
        return self._sock

    def quit(self):
        if self._sock:
            self._sock.close()
