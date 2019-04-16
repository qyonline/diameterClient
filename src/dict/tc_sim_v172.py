#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os
import time
import datetime
import socket
import threading, signal
from struct import pack, unpack, calcsize
from my_pcap import Pcap, Packet
import readline

TC_IP = "10.202.8.3"
PMU_PRI_IP = "10.202.8.14"
CONTROL_PORT = 3700
USR_PKG_PORT = 3900
USR_EVT_PORT = 3901
PCAP_FILE = "/data/jacky/pcap/1296_r.pcap"

SOCKET_BUF_SIZE = 1024
# message type
MSG_TYPE_RULE_ADD_REQ = 0x01
MSG_TYPE_RULE_ADD_ACK = 0X02
MSG_TYPE_RULE_DEL_REQ = 0x03
MSG_TYPE_RULE_DEL_ACK = 0X04
MSG_TYPE_KEEP_ALIVE_REQ = 0x10
MSG_TYPE_KEEP_ALIVE_ACK = 0x11
MSG_TYPE_F_PRC_PKG_REQ = 0xE0
MSG_TYPE_F_PRC_PKG_ACK = 0xE1
MSG_TYPE_F_EVT_RPT_REQ = 0xE4
MSG_TYPE_F_EVT_RPT_ACK = 0xE5
MSG_TYPE_RST_REQ = 0xF4
MSG_TYPE_RST_ACK = 0xF5

# MSG_VERSION = 0x11
MSG_VERSION = 0x40
MAX_SEQ_ID = 0xFFFFFFFF
MAX_RULE_ID = 0xFFFFFFFF

# message struct
STRUCT_PUBLIC_MSG_HEADER = "!2BHI"
STRUCT_KEEP_ALIVE_MSG = STRUCT_PUBLIC_MSG_HEADER
STRUCT_RULE_ADD_REQ = STRUCT_PUBLIC_MSG_HEADER + "4I4HBHB2I4BI16s"
STRUCT_RULE_ADD_ACK = STRUCT_PUBLIC_MSG_HEADER + "4BI"
STRUCT_RULE_DEL_REQ = STRUCT_PUBLIC_MSG_HEADER + "5I2BH16s"
STRUCT_RULE_DEL_ACK = STRUCT_PUBLIC_MSG_HEADER + "2BH"

STRUCT_F_PRC_PKG_REQ = STRUCT_PUBLIC_MSG_HEADER + "16sI2BH"  # no raw data
STRUCT_F_PRC_PKG_ACK = STRUCT_PUBLIC_MSG_HEADER + "I2BH3I2H3I2H"  # no modify data
STRUCT_F_EVT_RPT_REQ = STRUCT_PUBLIC_MSG_HEADER + "16sI2BH2I"
STRUCT_F_EVT_RPT_ACK = STRUCT_PUBLIC_MSG_HEADER + "I2BHI"

STRUCT_RST_REQ = STRUCT_PUBLIC_MSG_HEADER
STRUCT_RST_ACK = STRUCT_PUBLIC_MSG_HEADER

# msessage struct length
MSG_LEN_PUBLIC_MSG_HEADER = calcsize(STRUCT_PUBLIC_MSG_HEADER)
MSG_LEN_KEEP_ALIVE = calcsize(STRUCT_KEEP_ALIVE_MSG)
MSG_LEN_RULE_ADD_ACK = calcsize(STRUCT_RULE_ADD_ACK)
MSG_LEN_RULE_DEL_ACK = calcsize(STRUCT_RULE_DEL_ACK)

MSG_LEN_F_PRC_PKG_REQ_NO_RAW_DATA = calcsize(STRUCT_F_PRC_PKG_REQ)
MSG_LEN_F_PRC_PKG_ACK_NO_MDIFY_DATA = calcsize(STRUCT_F_PRC_PKG_ACK)
MSG_LEN_F_EVT_RPT_REQ = calcsize(STRUCT_F_EVT_RPT_REQ)
MSG_LEN_F_EVT_RPT_ACK = calcsize(STRUCT_F_EVT_RPT_ACK)

MSG_LEN_RST_REQ = calcsize(STRUCT_RST_REQ)
MSG_LEN_RST_ACK = calcsize(STRUCT_RST_ACK)

UP_DIRECTION_BASE_USER = 1
DOWN_DIRECTION_BASE_USER = 2


class Rule_Add_Req(object):
    def __init__(self, data):
        self.msg_type, self.msg_version, self.length, self.seq_id, \
        self.outer_src_ip, self.outer_dst_ip, self.inner_src_ip, self.inner_dst_ip, \
        self.outer_src_port, self.outer_dst_port, self.inner_src_port, self.inner_dst_port, \
        self.base, self.offset, self.rsvd, self.offset_value, self.mask, \
        self.phy_port, self.rule_type, self.packet_parameter, self.controller, \
        self.volume_parameter, self.correlation_info = unpack(STRUCT_RULE_ADD_REQ, data)

        self.rule_id = 0

    def show(self):
        format = "rule_add_req:\n" + \
                 "  |-msg_type = %#x\n" + \
                 "  |-msg_version = %#x\n" + \
                 "  |-length = %d\n" + \
                 "  |-seq_id = %d\n" + \
                 "  |-outer_src_ip = %#x\n" + \
                 "  |-outer_dst_ip = %#x %s\n" + \
                 "  |-inner_src_ip = %#x %s\n" + \
                 "  |-inner_dst_ip = %#x\n" + \
                 "  |-outer_src_port = %d\n" + \
                 "  |-outer_dst_port = %d\n" + \
                 "  |-inner_src_port = %d\n" + \
                 "  |-inner_dst_port = %d\n" + \
                 "  |-base = %d\n" + \
                 "  |-offset = %d\n" + \
                 "  |-rsvd = %d\n" + \
                 "  |-max_uplink_bps = %d\n" + \
                 "  |-max_downlink_bps = %d\n" + \
                 "  |-phy_port = %d\n" + \
                 "  |-rule_type = %#x\n" + \
                 "  |-packet_parameter = %d\n" + \
                 "  |-controller = %d\n" + \
                 "  |-volume_parameter = %d\n" + \
                 "  |-correlation_info = %s\n"

        outer_dst_ip_str = socket.inet_ntoa(pack('I',socket.htonl(self.outer_dst_ip)))
        inner_src_ip_str = socket.inet_ntoa(pack('I',socket.htonl(self.inner_src_ip)))
        print type(outer_dst_ip_str)
        print "outer_dst_ip_str = %s" % outer_dst_ip_str
        print format % (self.msg_type, self.msg_version, self.length, self.seq_id, \
                        self.outer_src_ip, self.outer_dst_ip, outer_dst_ip_str, self.inner_src_ip, inner_src_ip_str, self.inner_dst_ip, \
                        self.outer_src_port, self.outer_dst_port, self.inner_src_port, self.inner_dst_port, \
                        self.base, self.offset, self.rsvd, self.offset_value, self.mask, \
                        self.phy_port, self.rule_type, self.packet_parameter, self.controller, \
                        self.volume_parameter, list(unpack("16B", self.correlation_info)))



class Rule_Add_Ack(object):
    def __init__(self, seq_id, rule_id):
        self.msg_type = MSG_TYPE_RULE_ADD_ACK
        self.msg_version = MSG_VERSION
        self.length = MSG_LEN_RULE_ADD_ACK
        self.seq_id = seq_id
        self.res_code = 0  # 0:success 1:failed
        self.rsvd1 = 0
        self.rsvd2 = 0
        self.rsvd3 = 0
        self.rule_id = rule_id
        self.bin_data = pack(STRUCT_RULE_ADD_ACK,
                             self.msg_type, self.msg_version, self.length, self.seq_id, \
                             self.res_code, self.rsvd1, self.rsvd2, self.rsvd3, self.rule_id)


class Rule_Del_Req(object):
    def __init__(self, data):
        self.msg_type, self.msg_version, self.length, self.seq_id, \
        self.rule_id, \
        self.outer_src_ip, self.outer_dst_ip, self.inner_src_ip, self.inner_dst_ip, \
        self.rule_type, self.phy_port, self.rsvd, self.correlation_info = \
            unpack(STRUCT_RULE_DEL_REQ, data)

    def show(self):
        format = "rule_del_req:\n" + \
                 "  |-msg_type = %#x\n" + \
                 "  |-msg_version = %#x\n" + \
                 "  |-length = %d\n" + \
                 "  |-seq_id = %d\n" + \
                 "  |-rule_id = %d\n" + \
                 "  |-outer_src_ip = %#x\n" + \
                 "  |-outer_dst_ip = %#x\n" + \
                 "  |-inner_src_ip = %#x\n" + \
                 "  |-inner_dst_ip = %#x\n" + \
                 "  |-rule_type = %#x\n" + \
                 "  |-phyport = %d\n" + \
                 "  |-correlation_info = %s\n"
        print format % (self.msg_type, self.msg_version, self.length, self.seq_id, \
                        self.rule_id, \
                        self.outer_src_ip, self.outer_dst_ip, self.inner_src_ip, self.inner_dst_ip, \
                        self.rule_type, self.phy_port, list(unpack("16B", self.correlation_info)))


class Rule_Del_Ack(object):
    def __init__(self, seq_id):
        self.msg_type = MSG_TYPE_RULE_DEL_ACK
        self.msg_version = MSG_VERSION
        self.length = MSG_LEN_RULE_DEL_ACK
        self.seq_id = seq_id
        self.res_code = 0  # 0:success 3:seqid invalid
        self.rsvd1 = 0
        self.rsvd2 = 0
        self.bin_data = pack(STRUCT_RULE_DEL_ACK,
                             self.msg_type, self.msg_version, self.length, self.seq_id, \
                             self.res_code, self.rsvd1, self.rsvd2)


class F_PRC_PKG_REQ(object):
    def __init__(self, seq_id, cor_info, flow_id, phy_port, packet, rule):
        self.msg_type = MSG_TYPE_F_PRC_PKG_REQ
        self.msg_version = MSG_VERSION
        self.length = MSG_LEN_F_PRC_PKG_REQ_NO_RAW_DATA + len(packet.data)
        self.seq_id = seq_id
        self.cor_info = cor_info
        self.flow_id = flow_id
        self.phy_port = phy_port
        self.rsvd1 = 0
        self.rsvd2 = 0
        self.packet = packet
        self.raw_data = packet.data

        self.set_direction(rule)
        self.bin_data = pack(STRUCT_F_PRC_PKG_REQ + "%ds" % len(self.raw_data),
                             self.msg_type, self.msg_version, self.length, self.seq_id, \
                             self.cor_info, self.flow_id, self.phy_port, self.rsvd1, self.rsvd2, self.raw_data)

    def set_direction(self, rule):
        rule_inner_src_ip = rule.inner_src_ip
        rule_outer_dst_ip = rule.outer_dst_ip

        pkg_inner_src_ip = self.packet.inner_src_ip
        pkg_outer_dst_ip = self.packet.outer_dst_ip

        pkg_inner_dst_ip = self.packet.inner_dst_ip
        pkg_outer_src_ip = self.packet.outer_src_ip

        if rule_inner_src_ip == pkg_inner_src_ip and \
                        rule_outer_dst_ip == pkg_outer_dst_ip:
            self.cor_info = self.cor_info[:-1] + pack("B", UP_DIRECTION_BASE_USER)
        elif rule_inner_src_ip == pkg_inner_dst_ip and \
                        rule_outer_dst_ip == pkg_outer_src_ip:
            self.cor_info = self.cor_info[:-1] + pack("B", UP_DIRECTION_BASE_USER)

    def show(self):
        # print self.flow_id
        # print self.phy_port
        format = "F_PRC_PKG_REQ:\n" + \
                 "  |-msg_type = %#x\n" + \
                 "  |-msg_version = %#x\n" + \
                 "  |-length = %d\n" + \
                 "  |-seq_id = %d\n" + \
                 "  |-cor_info = %s\n" + \
                 "  |-direction = %d\n" + \
                 "  |-flow_id = %d\n" + \
                 "  |-phy_port = %d\n"
        print format % (self.msg_type, self.msg_version, self.length, self.seq_id, \
                        list(unpack("16B", self.cor_info)), unpack("B", self.cor_info[-1])[0], self.flow_id,
                        self.phy_port)


class F_PRC_PKG_ACK(object):
    def __init__(self, data):
        self.msg_type, self.msg_version, self.length, self.seq_id, \
        self.flow_id, self.phy_port, self.action, self.rewrite_port, \
        self.rewrite_ip, self.org_src_ip, self.org_dst_ip, \
        self.org_src_port, self.org_dst_port \
        self.ggsn_ip, self.total_volume_granularity, self.app_id \
        self.app_group_id, self.rsv = \
            unpack(STRUCT_F_PRC_PKG_ACK, data[:MSG_LEN_F_PRC_PKG_ACK_NO_MDIFY_DATA])

        if self.action == 0:
            self.modify_data = data[MSG_LEN_F_PRC_PKG_ACK_NO_MDIFY_DATA:]

    def show(self):
        format = "F_PRC_PKG_ACK:\n" + \
                 "  |-msg_type = %#x\n" + \
                 "  |-msg_version = %#x\n" + \
                 "  |-length = %d\n" + \
                 "  |-seq_id = %d\n" + \
                 "  |-flow_id = %d\n" + \
                 "  |-phy_port = %d\n" + \
                 "  |-action = %d\n" + \
                 "  |-rewrite_port = %d\n" + \
                 "  |-rewrite_ip = %#x %s\n" + \
                 "  |-org_src_ip = %#x %s\n" + \
                 "  |-org_dst_ip = %#x %s\n" + \
                 "  |-org_src_port = %d\n" + \
                 "  |-org_dst_port = %d\n" + \
                 "  |-ggsn_ip = %#x %s\n" + \
                 "  |-total_volume_granularity = %d\n" + \
                 "  |-app_id = %d\n" + \
                 "  |-app_group_id = %d\n"
        rewrite_ip_str = socket.inet_ntoa(pack('I',socket.htonl(self.rewrite_ip)))
        org_src_ip_str = socket.inet_ntoa(pack('I',socket.htonl(self.org_src_ip)))
        org_dst_ip_str = socket.inet_ntoa(pack('I',socket.htonl(self.org_dst_ip)))
        ggsn_ip_str = socket.inet_ntoa(pack('I',socket.htonl(self.ggsn_ip)))
        print format % (self.msg_type, self.msg_version, self.length, self.seq_id, \
                        self.flow_id, self.phy_port, self.action, self.rewrite_port, \
                        self.rewrite_ip, rewrite_ip_str, self.org_src_ip, org_src_ip_str, self.org_dst_ip, org_dst_ip_str\
                        self.org_src_port, self.org_dst_port \
                        self.ggsn_ip, ggsn_ip_str, self.total_volume_granularity, self.app_id \
                        self.app_group_id)


class Rst_Msg_Req(object):
    def __init__(self, seq_id):
        self.msg_type = MSG_TYPE_RST_REQ
        self.msg_version = MSG_VERSION
        self.length = MSG_LEN_RST_REQ
        self.seq_id = seq_id
        self.bin_data = pack(STRUCT_RST_REQ,
                             self.msg_type, self.msg_version, self.length, self.seq_id)


class TC(object):
    def __init__(self):
        self.tc_ip = TC_IP
        self.pmu_pri_ip = PMU_PRI_IP
        self.pmu_sec_ip = ""

        self.mng_port = 21008
        self.control_port = CONTROL_PORT
        self.usr_port = USR_PKG_PORT
        self.usr_pkg_port = USR_PKG_PORT
        self.usr_evt_port = USR_EVT_PORT

        self.mng_socket = None
        self.mng_client = None
        self.pri_keep_alive_req_socket = None
        self.sec_keep_alive_req_socket = None
        self.pri_keep_alive_ack_socket = None
        self.sec_keep_alive_ack_socket = None
        self.control_server = None
        self.usr_server = None

        self.seq_id = 0
        self.rule_id = 0
        self.is_alive = True

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.thread_pool = []
        self.gtpu_rule_dict = {}

    def signal_handler(self, sig, frame):
        if sig == signal.SIGINT or sig == signal.SIGTERM:
            self.is_alive = False

    def show_help(self):
        help = "Send F_PRC_PKG_REQ: PKG d:/Projects/TC_Sim/src/1296_r.pcap 0 \r\n" + \
               "Send F_EVT_RPT_REQ: EVT\r\n" + \
               "[TC_Sim]#"
        self.mng_client.send(help)

    def show_cmd_line(self, out_put=""):
        if len(out_put) > 0:
            self.mng_client.send(out_put)
        self.mng_client.send("[TC_Sim]#")

    def proc_pkg_req(self, cmd):
        args = cmd.split()
        file_name = args[1]
        pcap = Pcap(PCAP_FILE)

        # only send 1 packet
        if args[1]:
            idx = int(args[1])
            packet = pcap.packet_list[idx]
            uplink_rule_key = "%x_%x" % (packet.inner_src_ip, packet.outer_dst_ip)
            downlink_rule_key = "%x_%x" % (packet.inner_dst_ip, packet.outer_src_ip)
            rule_key = ""
            if uplink_rule_key in self.gtpu_rule_dict.keys():
                rule_key = uplink_rule_key
            elif downlink_rule_key in self.gtpu_rule_dict.keys():
                rule_key = downlink_rule_key

            if len(rule_key) == 0:
                print "packet %d didn't match any gtpu rule!" % idx
                return

            rule = self.gtpu_rule_dict[rule_key]
            seq_id = rule.seq_id
            cor_info = rule.correlation_info
            flow_id = packet.flow_id
            phy_port = rule.phy_port
            pkg_req = F_PRC_PKG_REQ(seq_id, cor_info, flow_id, phy_port, packet, rule)
            pkg_req.show()
            self.send_data_to_pmu((self.pmu_pri_ip, self.usr_port), pkg_req.bin_data)
        else:
            # send all packets
            for idx, packet in enumerate(pcap.packet_list):
                uplink_rule_key = "%x_%x" % (packet.inner_src_ip, packet.outer_dst_ip)
                downlink_rule_key = "%x_%x" % (packet.inner_dst_ip, packet.outer_src_ip)
                rule_key = ""
                if uplink_rule_key in self.gtpu_rule_dict.keys():
                    rule_key = uplink_rule_key
                elif downlink_rule_key in self.gtpu_rule_dict.keys():
                    rule_key = downlink_rule_key
                if len(rule_key) == 0:
                    print "packet %d didn't match any gtpu rule!" % idx
                    continue

                rule = self.gtpu_rule_dict[rule_key]
                seq_id = rule.seq_id
                cor_info = rule.correlation_info
                flow_id = packet.flow_id
                phy_port = rule.phy_port
                pkg_req = F_PRC_PKG_REQ(seq_id, cor_info, flow_id, phy_port, packet.data)
                self.send_data_to_pmu((self.pmu_pri_ip, self.usr_port), pkg_req.bin_data)

    def proc_cmd(self, cmd):
        cmd = cmd.strip()
        if "PKG" == cmd[:3] or "pkg" == cmd[:3]:
            self.proc_pkg_req(cmd)

        elif "EVT" == cmd[:3]:
            pass

    def mng_service(self):
        while True:
            data = raw_input("[TC_Sim]#")
            self.proc_cmd(data)

    def send_keep_alive_req(self, pmu_ip):
        addr = (pmu_ip, self.control_port)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # client.settimeout(5)
        if pmu_ip == self.pmu_pri_ip:
            self.pri_keep_alive_req_socket = client
        else:
            self.sec_keep_alive_req_socket = client

        rst_req = Rst_Msg_Req(0)
        client.sendto(rst_req.bin_data, addr)
        while True:
            if not self.is_alive:
                break;
            # msg_type:1 msg_ver:1 length:2 seq_id:4
            keep_alive_req = pack(STRUCT_KEEP_ALIVE_MSG,
                                  MSG_TYPE_KEEP_ALIVE_REQ,
                                  MSG_VERSION,
                                  MSG_LEN_KEEP_ALIVE,
                                  self.seq_id)
            send_len = client.sendto(keep_alive_req, addr)
            # print "send_keep_alive_req send to %s:%d send_len=%d" % (addr[0], addr[1], send_len)
            if send_len != MSG_LEN_KEEP_ALIVE:
                print "send keep alive req to %s failed! seq_id=%d" % (pmu_ip, self.seq_id)
            self.seq_id = (self.seq_id + 1) % MAX_SEQ_ID
            time.sleep(1)
        client.close()
        print "send_keep_alive_req close socket"

    def send_data_to_pmu(self, addr, data):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_len = client.sendto(data, addr)
        if send_len != len(data):
            msg_type = unpack("!I", data[:4])
            print "send_data_to_pmu failed! msg_type=%#x" % (msg_type)
        client.close()

    def send_f_prc_pkg_req(self, pcap):
        pass

    def send_f_evt_rpt_req(self):
        pass

    def control_port_server(self):
        self.control_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.control_server.bind((self.tc_ip, self.control_port))

        while True:
            data, addr = self.control_server.recvfrom(SOCKET_BUF_SIZE)
            msg_type, msg_ver, length, seq_id = unpack(STRUCT_KEEP_ALIVE_MSG, data[:MSG_LEN_PUBLIC_MSG_HEADER])
            # print "control_port_server: msg_type=%X, msg_ver=%X, length=%d, seq_id=%d" % (msg_type, msg_ver, length, seq_id)
            if msg_type == MSG_TYPE_KEEP_ALIVE_ACK:
                pass

            elif msg_type == MSG_TYPE_RULE_ADD_REQ:
                rule = Rule_Add_Req(data)
                rule.show()
                rule_key = "%x_%x" % (rule.inner_src_ip, rule.outer_dst_ip)
                try:
                    rule_in_dict = self.gtpu_rule_dict[rule_key]
                except KeyError:
                    rule_in_dict = None
                if not rule_in_dict:
                    self.rule_id = (self.rule_id + 1) % MAX_RULE_ID
                    rule.rule_id = self.rule_id
                    self.gtpu_rule_dict[rule_key] = rule

                rule_add_ack = Rule_Add_Ack(rule.seq_id, rule.rule_id)
                self.send_data_to_pmu((addr[0], self.control_port), rule_add_ack.bin_data)

            elif msg_type == MSG_TYPE_RULE_DEL_REQ:
                rule_del_req = Rule_Del_Req(data)
                rule_key = "%x_%x" % (rule_del_req.inner_src_ip, rule_del_req.outer_dst_ip)
                try:
                    rule_in_dict = self.gtpu_rule_dict[rule_key]
                except KeyError:
                    rule_in_dict = None
                rule_del_ack = Rule_Del_Ack(rule_del_req.seq_id)
                if not rule_in_dict:
                    rule_del_ack.res_code = 3
                else:
                    del self.gtpu_rule_dict[rule_key]

                self.send_data_to_pmu((addr[0], self.control_port), rule_del_ack.bin_data)
            elif msg_type == MSG_TYPE_RST_ACK:
                print "received a rst_ack message!"

            else:
                print "control_port_server received an unknown message, msg_type=%#x" % msg_type

    def usr_port_server(self):
        self.usr_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.usr_server.bind((self.tc_ip, self.usr_pkg_port))

        while True:
            data, addr = self.usr_server.recvfrom(SOCKET_BUF_SIZE)
            msg_type, msg_ver, length, seq_id = unpack(STRUCT_KEEP_ALIVE_MSG, data[:MSG_LEN_PUBLIC_MSG_HEADER])
            print "usr_server: msg_type=%X, msg_ver=%X, length=%d, seq_id=%d" % (msg_type, msg_ver, length, seq_id)
            if msg_type == MSG_TYPE_F_PRC_PKG_ACK:
                pkg_ack = F_PRC_PKG_ACK(data)
                print "F_PRC_PKG_ACK len=%d" % (len(data))
                pkg_ack.show()
            elif msg_type == MSG_TYPE_F_EVT_RPT_ACK:
                pass

    def start_all_threads(self):
        t = threading.Thread(target=self.mng_service)
        self.thread_pool.append(t)

        t = threading.Thread(target=self.send_keep_alive_req, args=(self.pmu_pri_ip,))
        self.thread_pool.append(t)
        t = threading.Thread(target=self.control_port_server)
        self.thread_pool.append(t)
        t = threading.Thread(target=self.usr_port_server)
        self.thread_pool.append(t)

        if self.pmu_sec_ip:
            t = threading.Thread(target=self.send_keep_alive_req, args=(self.pmu_sec_ip,))
            self.thread_pool.append(t)

        for t in self.thread_pool:
            t.setDaemon(True)
            t.start()

    def close_all_socekt(self):
        if self.mng_client:
            self.mng_client.close()
        if self.mng_socket:
            self.mng_socket.close()

        if self.pri_keep_alive_req_socket:
            self.pri_keep_alive_req_socket.close()
        if self.sec_keep_alive_req_socket:
            self.sec_keep_alive_req_socket.close()

        if self.control_server:
            self.control_server.close()
        if self.usr_server:
            self.usr_server.close()

    def start_tc(self):
        self.start_all_threads()
        while True:
            if not self.is_alive:
                break;
        self.close_all_socekt()
        print "TC has exited."


if __name__ == '__main__':
    tc = TC()
    tc.start_tc()
