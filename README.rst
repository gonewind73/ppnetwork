PPNetwork

========

PPNetwork 是无中心节点的网络驱动，包括 pp_link，pp_control，pp_flow 三部分
每个节点都具备控制和连接功能。无集中控制器

PPNode
PPLink
PPBase




pp_link
---------
类似于链路层，主要实现ppnetwork的基础功能

pp_control
------------
类似于SDN网络中的控制器，主要实现节点发现，心跳等信令机制

pp_flow
-------
类似于SDN网络中的数据流，主要实现节点的数据连接和交互


安装
=====

```	pip install python-ppnetwork
```

    
使用
=====

ppnetwork 不能独立运行，需要根据接口，开发上层应用。

from ppnet import PPDataNode

ppdatanode = PPDataNode(port=54320)
ppdatanode.set_peer(addr)
ppdatanode.send(data,addr1)
data,addr2 = ppdatanode.receive(count)






