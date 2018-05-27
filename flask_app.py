'''
Created on 2018年5月22日

@author: heguofeng
run on http://ppnetwork.pythonanywhere.com/ppnet/public  
'''

#!/usr/bin/env python
import datetime
from flask import Flask,request,Response
import json 
import requests
import os
import time

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello from Flask!'

'''
net_nodes =  { node_id:(ip,port,time}
p2p_net_nodes = { net_id: net_nodes} 
'''
p2p_net_nodes = {}  

@app.route('/ppnet/public',methods=['GET','POST'])
def public():
    if request.method == 'POST':
        net_id = request.args.get('net_id','4294967295')
        node_id = request.args.get('node_id','0')
        if node_id=="0":
            return 'error of  node_id'
        ip = request.args.get('ip','0.0.0.0')
        port = request.args.get('port','')
        nodes = p2p_net_nodes.get(net_id,{})
        if ip=="0.0.0.0": 
            if node_id in  nodes:
                nodes.pop(node_id)
        else:
            nodes[node_id] = (ip,port,int(time.time()))
        p2p_net_nodes[net_id] = nodes
        return 'total %d node in net %s ' % (len(nodes),net_id)
    else: #get
        net_id = request.args.get('net_id','4294967295')
        print("net_id",net_id)
        nodes = p2p_net_nodes.get(net_id,{})
        now = time.time()
        alive_node = {}
        for node in nodes:
            if now - nodes[node][2] < 60*60*24 :
                alive_node[node] = nodes[node]
        djson=json.dumps(alive_node)
        return  Response(djson)

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000, threaded=True)
