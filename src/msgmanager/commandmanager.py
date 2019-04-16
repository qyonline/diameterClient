#!/usr/bin/env python
#coding=utf-8
__author__ = 'jimyin'

import threading
import socket
import logging
import select
import os
from protocols import libdiameter

class CommandManager(threading.Thread):
    def __init__(self,thread_name,msg_queue,manager_port):
        threading.Thread.__init__(self,name=thread_name)
        self.msg_queue=msg_queue
        self.manager_port=manager_port
        self.msg_type=libdiameter.MSG_TERM.keys()

    def run(self):
        host=socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host,int(self.manager_port)))
        s.listen(5)
        logging.info("Management server is starting, lister on "+host+":"+str(self.manager_port))
        home=os.path.join(os.path.dirname(os.getcwd()),"conf")
        logging.info("The default configuration dir:"+home)

        while 1:
            # waiting for incoming connection
            in_fds,out_fds,err_fds = select.select([s,],[],[],1)
            if len(in_fds) != 0:
                client_sock,client_address=s.accept()
                logging.info("Manager port receive an connection from "+str(client_address))
                client_sock.sendall("AicentQATeam>")
                while 1:
                    con_in_fds,con_out_fds,con_err_fds = select.select([client_sock,],[],[],3)
                    if len(con_in_fds)!=0:
                        try:
                            buffer=client_sock.recv(1024).strip()
                        except socket.error:
                            logging.exception("")
                            client_sock.close()
                            logging.error("connect close by client ")
                            break
                        logging.info("input command:"+buffer)

                        if "home" in buffer and "=" in buffer:
                            home=buffer[buffer.find("=")+1:].strip()
                            logging.info("Set configuration files home directory to "+home)
                        elif "R" in buffer or "A" in buffer:
                            buffer = buffer.strip()
                            arg_list = buffer.split()
                            msg_type = arg_list[0]
                            if len(arg_list) > 1:
                                dia_cfg = arg_list[1]
                            else:
                                dia_cfg = "diameter.cfg"
                            if msg_type in libdiameter.MSG_TERM.keys():
                                msg_conf_file=os.path.join(home,dia_cfg)
                                avp_template_dic=libdiameter.avps_value_dic(msg_type,msg_conf_file)
                                #msg=libdiameter.create_msg(msg_type,libdiameter.HDRItem(),avp_template_dic)
                                msg=libdiameter.create_msg(msg_type,libdiameter.HDRItem(),msg_conf_file)
                                #queue content: ["ULA","/export/home/jim/conf/test11/diameter.cfg"]
                                self.msg_queue.put_nowait(msg.decode("hex"))
                            else:
                                logging.error("the input is error")
                        elif buffer=="exit":
                            logging.info("Exit the connection")
                            client_sock.close()
                            break
                        else:
                            logging.error("the input is error")
                        client_sock.sendall("AicentQATeam>")
