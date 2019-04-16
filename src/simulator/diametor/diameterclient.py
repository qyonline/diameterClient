#!/usr/bin/env python
#coding=utf-8
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3, Last change on Oct 30, 2012
# This software is distributed under the terms of BSD license.    
##################################################################
'''
Update-Location-Request	ULR	316	1
Update-Location-Answer	ULA	316	0
Cancel-Location-Request	CLR	317	1
Cancel-Location-Answer	CLA	317	0
Authentication-Information- Request	AIR	318	1
Authentication-Information-  Answer	AIA	318	0
Insert-Subscriber-Data-Request	IDR	319	1
Insert-Subscriber-Data-Answer	IDA	319	0
Delete-Subscriber-Data-Request	DSR	320	1
Delete-Subscriber-Data-Answer	DSA	320	0
Purge-UE-Request	PUR	321	1
Purge-UE-Answer	PUA	321	0
Reset-Request	RSR	322	1
Reset-Answer	RSA	322	0
Notify-Request	NOR	323	1
Notify-Answer	NOA	323	0
'''

from protocols import  libdiameter

import os
import time
import socket
import logging
import threading
import select
import binascii
from msgmanager import msgparser
from connection import receiver
from connection import sender


if os.name=='posix':
    try:
        import sctp
    except ImportError:
        logging.error("no sctp module, please install it by running src/tools/sctp/install.sh")

class KeepAliveClient(threading.Thread):

    def __init__(self,thread_name,sys_conf,msg_queue):
        threading.Thread.__init__(self,name=thread_name)
        self.msg_queue=msg_queue
        self.sys_conf=sys_conf
        self.sender=sender.diameter_sender(self.sys_conf)
        self.peer_ip=self.sys_conf["sysparm"]["peer_ip"]
        self.alive_port=int(self.sys_conf["sysparm"]["keep_alive_server_port"])
        self.protocol=self.sys_conf["sysparm"]["protocol"]
        self.keep_alive_duration=int(self.sys_conf["sysparm"]["keep_alive_duration"])
        
    def run(self):
        self.connection=self.setup_connection()
        failed_times=0
        keep_alive_body=(hex(int(64))[2:].zfill(1)+"Y".encode("hex")).decode("hex")
        while 1:                       
            #logging.info("send keep alive message")
            try:
                self.connection.send(keep_alive_body)
                k_in_fds,k_out_fds,k_err_fds = select.select([self.connection,],[],[])
                if len(k_in_fds) != 0:
                    response=self.connection.recv(4096)
                    #logging.info("The connection is available,response data:"+str(binascii.hexlify(response)).decode("hex"))
            except Exception,e:                
                logging.error(e)
                logging.error("The heartbeat socket was closed, try to reconnect...")
                time.sleep(5)
                self.connection=self.setup_connection()
                

            time.sleep(self.keep_alive_duration)

    def setup_connection(self):
        while 1:
            try:
                connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                connection.connect((self.peer_ip,self.alive_port ))
                connection.settimeout(None)
                logging.info("Setup heartbeat socket "+str(connection.fileno()))
                return connection
            except:
                #if server not start, will go here
                #reconnect until sucess
                time.sleep(5)

    def close_connection(self):
        self.connection.close()

class DiameterClient(threading.Thread):

    def __init__(self,thread_name,sys_conf,msg_queue):
        threading.Thread.__init__(self,name=thread_name)
        self.msg_queue=msg_queue
        self.sys_conf=sys_conf
        self.sender=sender.diameter_sender(self.sys_conf)
        self.peer_ip=self.sys_conf["sysparm"]["peer_ip"]
        self.port=int(self.sys_conf["sysparm"]["peer_port"])
        self.protocol=self.sys_conf["sysparm"]["protocol"]

    def run(self):
        self.client_connection=self.setup_connection()
        '''
        if self.client_connection:            
            client_receiver=receiver.ReceiverThread("ClientReceiver",self.sys_conf,self.msg_queue,self.client_connection)
            client_receiver.start()

            client_receiver.join()
        '''
        msgpar=msgparser.DiameterMsgParser()

        while 1:
            try:
                receiver_data=receiver.receive(self.client_connection)
                if receiver_data:
                    #logging.info("Receive data"+receiver_data)
                    msg,cmd=msgpar.msg_parser(receiver_data)
                    if msg:
                        msg = msg.decode("hex")
                        self.sender.send_diameter_msg(msg,self.client_connection)
                        logging.info("Send command: "+cmd)

                if not self.msg_queue.empty():
                    msg=self.msg_queue.get()
                    #logging.info(msg)
                    self.sender.send_diameter_msg(msg,self.client_connection)

            except Exception,e:
                logging.exception('exception in DiameterClient')
                logging.error("The diameter socket was closed, try to reconnect...")
                time.sleep(5)
                self.client_connection=self.setup_connection()        

    def setup_connection(self):
        while 1:
            try:
                connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                connection.connect((self.peer_ip,self.port ))
                connection.settimeout(1)
                logging.info("Setup service socket "+str(connection.fileno()))
                return connection
            except:
                #if server not start, will go here
                #reconnect until sucess
                time.sleep(5)

    def close_connection(self):
        self.client_connection.close()

