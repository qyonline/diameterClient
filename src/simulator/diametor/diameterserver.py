#!/usr/bin/env python
#coding=utf-8

import logging
import socket
import time
import select
import threading
import os
from protocols import libdiameter
from connection import  receiver
from connection import sender

if os.name=='posix':
    try:
        import sctp
    except ImportError:
        logging.error("no sctp module, please install it by running src/tools/sctp/install.sh")



class KeepAliveServer(threading.Thread):
    def __init__(self,thread_name,sys_conf,msg_queue):
        threading.Thread.__init__(self,name=thread_name)
        self.msg_queue=msg_queue
        self.sys_conf=sys_conf

    def run(self):
        keep_alive_body=(hex(int(64))[2:].zfill(1)+"Y".encode("hex")).decode("hex")
        host=socket.gethostbyname(socket.gethostname())
        port=int(self.sys_conf["sysparm"]["keep_alive_server_port"])
        if self.sys_conf["sysparm"]["protocol"].strip()=="SCTP":
            s = sctp.sctpsocket_tcp(socket.AF_INET)
        else:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host,port))
        s.listen(5)
        logging.info("Keep alive server is starting, lister on "+host+":"+str(port))
        while 1:
            in_fds,out_fds,err_fds = select.select([s,],[],[],3)
            if len(in_fds) != 0:
                server_sock,client_address=s.accept()
                logging.debug("keep alive server accept new connection from "+str(client_address)+".")
                while 1:
                    k_in_fds,k_out_fds,k_err_fds = select.select([server_sock,],[],[],3)
                    if len(k_in_fds) != 0:
                        k_data=server_sock.recv(4096)
                        logging.info("Receive keep alive message:"+k_data)
                        if k_data:
                            server_sock.send(keep_alive_body)
                        else:
                            logging.error("The connection is broken")
                            break
                    else:
                        time.sleep(2)
            else:
                time.sleep(2)

class DiameterServer(threading.Thread):
    def __init__(self,thread_name,sys_conf,msg_queue):
        threading.Thread.__init__(self,name=thread_name)
        self.msg_queue=msg_queue
        self.sys_conf=sys_conf

    def run(self):
        host=socket.gethostbyname(socket.gethostname())
        port=int(self.sys_conf["sysparm"]["port"])
        if self.sys_conf["sysparm"]["protocol"].strip()=="SCTP":
            s = sctp.sctpsocket_tcp(socket.AF_INET)
        else:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host,port))
        s.listen(5)
        logging.info("Diameter server is starting, lister on "+host+":"+str(port))
        i=1
        while 1:
            in_fds,out_fds,err_fds = select.select([s,],[],[],3)
            if len(in_fds) != 0:
                server_sock,client_address=s.accept()
                logging.debug("new connection come from "+str(client_address)+".")
                '''#move sender and revceive thread to on thread, so that control connnection convienent
                server_sender=sender.SenderThread("ServerSender"+str(i),self.sys_conf,self.msg_queue,server_sock)
                server_sender.start()
                '''
                server_receiver=receiver.ReceiverThread("ServerReceiver"+str(i),self.sys_conf,self.msg_queue,server_sock)
                server_receiver.start()
                i+=1
                #logging.info("There are "+str(i)+" connections")
            else:
                time.sleep(1)
                #logging.info("There are no new connection come")


class ServerConnection(threading.Thread):

    def __init__(self,thread_name,server_connection,cfg_file_dir):
        #TODO: once client close connection, how to remove connection from server
        threading.Thread.__init__(self,name=thread_name)
        self.server_connection=server_connection
        self.cfg_file_dir=cfg_file_dir

    def run(self):
        while 1:
            in_fds_c,out_fds_c,err_fds_c = select.select([self.server_connection,],[],[],3)

            data=receiver.receive(self.server_connection)
            if data:
                #logging.info("data hex value:"+data)
                H=libdiameter.HDRItem()
                libdiameter.stripHdr(H,data)
                avps=libdiameter.splitMsgAVPs(H.msg)
                cmd=libdiameter.dictCOMMANDcode2name(H.flags,H.cmd)
                logging.info("Command:"+cmd)
                if cmd==libdiameter.ERROR:
                    logging.error('Unknown command:'+H.cmd)
                else:
                    if cmd=="Credit-Control Request":
                        msg=libdiameter.create_msg(self.cfg_file_dir,"CCA")
                    elif cmd=="TDF-Session-Request Request":
                        msg=libdiameter.create_msg(self.cfg_file_dir,"TSA")

                    self.server_connection.sendall(msg.decode("hex"))
                logging.info("Hop-by-Hop="+str(H.HopByHop)+",End-to-End="+str(H.EndToEnd)+",ApplicationId="+str(H.appId))
                for avp in avps:
                    logging.info(avp+":"+str(libdiameter.decodeAVP(avp)))

            else:
                logging.info("no data coming on connection"+str(self.server_connection))
                time.sleep(1)

if __name__=='__main__':
    pass