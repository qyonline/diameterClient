#!/usr/bin/env python
#coding=utf-8
__author__ = 'jimyin'

import logging
import threading
import time

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


class SenderThread(threading.Thread):

    def __init__(self,thread_name,sys_conf,msg_queue,client_connection):
        threading.Thread.__init__(self,name=thread_name)
        self.msg_queue=msg_queue
        self.sys_conf=sys_conf
        self.client_connection=client_connection
        self.sender=diameter_sender(self.sys_conf)

    def run(self):
        while 1:
            if not self.msg_queue.empty():
                logging.debug("the queue length: "+str(self.msg_queue.qsize()))
                msg=self.msg_queue.get()
                self.sender.send_diameter_msg(msg,self.client_connection)

                '''
                if not self.sender.send_diameter_msg(msg,self.client_connection):
                    self.msg_queue.put_nowait(msg)
                    logging.debug("the queue length: "+str(self.msg_queue.qsize()))
                    logging.error("The socket was closed, exit the sender thread")
                    break
                    '''
                logging.debug("the queue length: "+str(self.msg_queue.qsize()))

            else:
                time.sleep(2)