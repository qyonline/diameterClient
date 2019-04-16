#!/usr/bin/env python
__author__ = 'jimyin'
#coding=utf-8

import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
reload(sys)
sys.setdefaultencoding('utf-8')


from aicent.configobj import ConfigObj
'''
sys_cfg_file=ConfigObj("../conf/diameter.cfg")
print sys_cfg_file.keys()
print sys_cfg_file["ULR"]["Vendor-Specific-Application-Id"]
print sys_cfg_file["ULR"]["Route-Record"]

'''
class CreateDiameterMsg:
    MSG_TERM={"ULR":"3GPP-Update-Location","ULA":"3GPP-Update-Location"}

    def __init__(self):
        pass
    def get_name(self,msg_type):
        print CreateDiameterMsg.MSG_TERM[msg_type]


cd=CreateDiameterMsg()
cd.get_name("ULR")
