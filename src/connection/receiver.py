#!/usr/bin/env python
#coding=utf-8
__author__ = 'jimyin'

import logging
import select
import socket
import binascii
import threading
from msgmanager import msgparser


def receive(connection):
    '''
    in_fds_c,out_fds_c,err_fds_c = select.select([connection,],[],[connection,],1)

    if len(in_fds_c) != 0:
        version_length=binascii.hexlify(connection.recv(4))
        if len(version_length)>0:
            logging.debug("verson_length:"+str(version_length))
            length=int(version_length[2:],16)
            return  version_length+binascii.hexlify(connection.recv(length-4))
        #return  connection.recv(4096)
    elif len(err_fds_c):
        raise Exception("select err")
    else:
        #logging.info("No data coming")
        return None
    '''
    try:
        version_length=binascii.hexlify(connection.recv(4))
        if len(version_length)>0:
            logging.debug("verson_length:"+str(version_length))
            length=int(version_length[2:],16)
            return version_length+binascii.hexlify(connection.recv(length-4))
        else:
            raise Exception("recv err")
    except socket.timeout:
        return None
class diameter_sender:
    def __init__(self,sys_conf):
        self.sys_conf=sys_conf
        self.protocol=sys_conf["sysparm"]["protocol"].strip()

    def send_diameter_msg(self,msg,connection):
        #logging.info("send msg with hex value:"+str(msg))
        if self.protocol=='SCTP':
            connection.sctp_send(msg)
        else:
            connection.sendall(msg)

class ReceiverThread(threading.Thread):

    def __init__(self,thread_name,sys_conf,msg_queue,client_connection):
        threading.Thread.__init__(self,name=thread_name)
        self.msg_queue=msg_queue
        self.sys_conf=sys_conf
        self.client_connection=client_connection
        self.sender=diameter_sender(self.sys_conf)

    def run(self):
        msgpar=msgparser.DiameterMsgParser()

        while 1:
            try:
                receiver_data=receive(self.client_connection)
            except Exception,e:
                logging.exception(e)
                logging.error("The socket was closed, exit the receiver thread")
                self.client_connection.close()
                break
            if receiver_data:
                logging.info("Receive data"+receiver_data)
                msg=msgpar.msg_parser(receiver_data)
                if msg:
                    self.msg_queue.put_nowait(msg.decode("hex"))

            if not self.msg_queue.empty():
                logging.debug("the queue length: "+str(self.msg_queue.qsize()))
                msg=self.msg_queue.get()
                self.sender.send_diameter_msg(msg,self.client_connection)

