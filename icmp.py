# coding: utf-8
import socket
import struct
import select
import sys

class RouteScanner:
    def __init__(self):
        # icmp socketを作成 ipヘッダーを修正する
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.soc.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)

    def checksum(self, data):
        data_len = len(data) // 2*2
        sum = 0
        for i in range(0,data_len,2):
            sum += (ord(data[i+1]) << 8) + ord(data[i])
            #Python3
            #sum += (ord(chr(data[i+1])) << 8) + ord(chr(data[i]))
        if len(data) % 2 != 0:
            sum += ord(data[-1])
            #Python3
            #sum += ord(chr(data[-1]))
        while sum >> 16:
            sum = (sum >> 16) + (sum & 0xffff)
        sum = sum >> 8 | (sum << 8 & 0xff00)
        return ~sum&0xffff

    # ipヘッダー作成
    def make_ip(self, target_ip, ttl):
        #固定の値はハードコード
        ip_ver = 4
        ip_hl  = 5
        ip_tos = 0
        ip_len = 28
        ip_id = 1
        ip_off = 0
        ip_ttl = ttl
        ip_proto = socket.IPPROTO_ICMP
        ip_check = 0
        ip_src = socket.inet_aton("0.0.0.0")
        ip_dst = socket.inet_aton(target_ip)
        ip_ver_hl = (ip_ver << 4) + ip_hl
        ip_header = struct.pack("!BBHHHBBH4s4s",ip_ver_hl,ip_tos,ip_len,ip_id,ip_off,ip_ttl,ip_proto,ip_check,ip_src,ip_dst)

        ip_check = self.checksum(ip_header)
        ip_header = struct.pack("!BBHHHBBH4s4s",ip_ver_hl,ip_tos,ip_len,ip_id,ip_off,ip_ttl,ip_proto,ip_check,ip_src,ip_dst)
        return ip_header

    # icmpヘッダー作成
    def make_icmp_echo_request(self):
        # 固定の値はハードコード
        # echo request
        type = 8
        code = 0
        check = 0
        id = 1
        seq = 1
        check = self.checksum(struct.pack("!BBHHH", type, code, check, id, seq))
        return struct.pack("!BBHHH", type, code, check, id, seq)

    # ipヘッダー取得
    def extract_ip(self, packet):
        #packで配列に変換 第一引数はipヘッダーに合うように指定
        return struct.unpack('!BBHHHBBH4s4s', packet)

    # スキャンします
    def scan(self, target_ip):
        print("Scanning to {} ...".format(target_ip))
        # 到達したかどうか
        reach = 0
        # 1~255まで確認
        for i in range(1, 256):
            ip = self.make_ip(target_ip, i)
            icmp = self.make_icmp_echo_request()
            packet = ip+icmp
            # 3回繰り返す
            for _ in range(3):
                self.soc.sendto(packet, (target_ip, 0))
                # socketがreadyになるのを待つ
                sel_res = select.select([self.soc],[],[],3)
                if len(sel_res[0]) > 0:
                    packet, addr = sel_res[0][0].recvfrom(1024)
                    ip = self.extract_ip(packet[0:20])
                    start = (ip[0]&0x0f)*4
                    res = self.analyze(packet[start:start+8])

                    if res == 1: #到達した
                        print("- Reach time to live {} from {}".format(i, addr[0]))
                        reach = 1
                        break
                    elif res == 0: #途中ノードから返ってきた
                        print("- time to live {} from {}".format(i, addr[0]))
                        break
            # 到達したのでループを抜ける
            if reach == 1:
                break


    # パケットを確認
    def analyze(self,packet):
        icmp = struct.unpack("!BBHHH", packet)

        if icmp[0] == 0: # エコー応答なら
            return 1 # 到達した
        elif icmp[0] == 11: # 時間超過なら
            return 0 # 到達していない
        return 2 #一応2を返しておく
