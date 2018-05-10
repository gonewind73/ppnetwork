# PPNet 设计

## 安全性考虑
1.  任何节点接入都需要验证，网络号+密钥 。 验证方法为： hmac(self.node_id,net_id,net_secret,sequence)[:4]
2.  控制信令都需要验证。
3.  数据连接建立基于控制信令。后续交互由应用决定。数据加密由上层应用决定。
4.  对公共节点信息，仅接受 beat 信令   hmac =  0 
5.  公共节点需要3个节点以上仲裁 才能加入

## 公共节点
1.  接受hmac为任何信息
2.  仅转发控制信令和数据。

## 激励原则
1. 按转发流量、时段、区域（时延） 激励 
