#!/usr/bin/env python
#coding=utf-8

import sys
import os
import logging
import Queue
import threading
from os.path import getsize
from time import sleep

#Add src root dirctory to PYTHONPATH by extend sys.path
#sys.path.append(sys.modules[__name__].__file__)
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
reload(sys)
sys.setdefaultencoding('utf-8')

os.chdir(os.path.dirname(os.path.realpath(__file__)))

from aicent.configobj import ConfigObj
from simulator.diametor import diameterclient
from simulator.diametor import diameterserver
from protocols import  libdiameter
from msgmanager import commandmanager

LOG_FILE = "../log/sim.log"
MAX_LOG_SIZE = 1024 * 1024 * 10 #10M


def log_monitor():
    while True:
	    log_size = getsize(LOG_FILE)
	    #logging.error("log_size=" + str(log_size) + " max_log_size=" + str(MAX_LOG_SIZE))
	    if log_size > MAX_LOG_SIZE:
	        os.system("echo > " + LOG_FILE)
	    
	    sleep(10)
 
#sys use default path, if there is no configuration file is assigned
#python peeringtcpsimulator.py client/server

def startSimulator():
    #cfg_instance=config = ConfigObj(filename)

    cfg_file_dir=""
    if len(sys.argv)==4:
        cfg_file_dir=sys.argv[3]
    else:
        cfg_file_dir=os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),"conf")

    sys_cfg_file=ConfigObj(os.path.join(cfg_file_dir, 'aps.cfg'))

    log_level=int(sys_cfg_file["sysparm"]["log_level"])
    logging.basicConfig(filename=LOG_FILE,level=log_level,format='%(asctime)s %(threadName)s %(levelname)s %(module)s:%(lineno)d %(message)s')

    monitor_thread = threading.Thread(target=log_monitor)
    monitor_thread.setDaemon(True)
    monitor_thread.start()

    msg_queue=Queue.Queue()
    if sys.argv[1].strip()=="diameter":
        libdiameter.LoadDictionary("dict/diameter.xml")
        libdiameter.APPID=int(sys_cfg_file["sysparm"]["app_id"])
        #dc=diameterclient.CreateDiameterMsg(sys_cfg_file,cfg_file_dir)
        #diameter_cfg_file=ConfigObj(os.path.join(cfg_file_dir, 'diameter.cfg'))

        #msg_types=["ULR","ULA","CLR","CLA","AIR","AIA","PUR","PUA","IDR","IDA","DSR","DSA","RSR","RSA","NOR","NOA"]
        #msg_types=["AIR","AIA","PUR","PUA","IDR","IDA","DSR","DSA","RSR","RSA","NOR","NOA"]

        if sys.argv[2].strip()=="client":
            for i in range(3):
                dc=diameterclient.DiameterClient("DiameterClient",sys_cfg_file,msg_queue)
                dc.start()
            ka=diameterclient.KeepAliveClient("KeepAliveClient",sys_cfg_file,msg_queue)
            ka.start()

        elif  sys.argv[2].strip()=="server":
            ds=diameterserver.DiameterServer("DiameterServer",sys_cfg_file,msg_queue)
            ks=diameterserver.KeepAliveServer("KeepAliveServer",sys_cfg_file,msg_queue)
            ks.start()
            ds.start()
        cm=commandmanager.CommandManager("CommandManager",msg_queue,int(sys_cfg_file["sysparm"]["mng_port"]))
        cm.start()
        cm.join()



    elif sys.argv[1].strip()=="smpp":
        pass
    else:
        print "input parameter error"
        sys.exit(1)

if __name__=="__main__":
    startSimulator()
    
