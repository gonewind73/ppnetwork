# coding=utf-8


version = "1.0.4.0"

PP_APPID = {
    "Raw": 0,
    "Auth": 1,
    "Beat": 7,
    "Ack": 8,
    "PathReq": 2,
    "PathRes": 3,
    "Text": 4,
    "FileCommand": 20,
    "File": 21,
    "Shell": 22,
    "Storage": 30,
    "NetManage": 161,
    "Sock5": 17,
    "Proxy": 18,
    "Data": 19,
    "VPN": 15,
}

BroadCastId = b"ffffff"
PublicNetId = 0xffffffff

NAT_TYPE = {"Unknown": 7, "Turnable": 2, "Unturnable": 5}
NAT_STRING = {2: "Turnable", 7: "Unknown", 5: "Unturnable",0:"Unknown"}

_BEAT_CMD = {"beat_req": 1,
             "beat_res": 2,
             "beat_set": 3,
             "offline": 4,
             "echo_req": 5,
             "echo_res": 6,
             }
