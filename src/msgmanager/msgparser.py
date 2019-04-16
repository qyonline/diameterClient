#!/usr/bin/env python
#coding=utf-8
__author__ = 'jimyin'

from protocols import libdiameter
import logging

class DiameterMsgParser:

    def __init__(self):
        pass

    def get_msg_term(self,cmd):
        if cmd.split()[1].strip()=="Request":
            cmd_name=cmd.split()[0]
            for k, v in libdiameter.MSG_TERM.iteritems():
                if v==cmd_name and k.endswith("A"):
                    return k
            return None
        else:
            return None

    def msg_parser(self,data):
        avp_dic={}
        #logging.info("data hex value:"+data)
        H=libdiameter.HDRItem()
        libdiameter.stripHdr(H,data)
        avps=libdiameter.splitMsgAVPs(H.msg)
        cmd=libdiameter.dictCOMMANDcode2name(H.flags,H.cmd)
        logging.info("Recv command: "+cmd)
        if cmd==libdiameter.ERROR:
            logging.error('Unknown command:'+H.cmd)
            return  None
        else:
            for avp in avps:
                decode_avp_para=libdiameter.decodeAVP(avp)
                if avp_dic.has_key(decode_avp_para[0]):
                    avp_dic[decode_avp_para[0]]=avp_dic[decode_avp_para[0]].append(str(decode_avp_para[1]))
                else:
                    avp_dic[decode_avp_para[0]]=[str(decode_avp_para[1])]

                #logging.debug(decode_avp_para[0]+":"+decode_avp_para[1])

            logging.debug("In coming avps dic:"+str(avp_dic))
            answer_cmd=self.get_msg_term(cmd)
            if answer_cmd:
                logging.debug(answer_cmd)
                avp_template_dic=libdiameter.avps_value_dic(answer_cmd)
                logging.debug(avp_template_dic)
                msg=libdiameter.create_msg(answer_cmd,H,self.change_msg_value(avp_template_dic,avp_dic,answer_cmd))
                logging.debug("Hop-by-Hop="+str(H.HopByHop)+",End-to-End="+str(H.EndToEnd)+",ApplicationId="+str(H.appId))
                return  msg,answer_cmd
            else:
                #logging.warn("Can not get related answer cmd, it is a request command or unknow command")
                return  None,None


    def change_msg_value(self,template_dic,in_avps_dic,msg_type):
        logging.debug("Change avp value from request")
        if template_dic.has_key("Session-Id"):
            if "auto" in template_dic["Session-Id"]:
                template_dic["Session-Id"]=libdiameter.create_Session_Id("www.aicent.com","0086136")
            else:
                template_dic["Session-Id"]=in_avps_dic["Session-Id"]
        if in_avps_dic.has_key("CC-Request-Type"):
            template_dic["CC-Request-Type"]=in_avps_dic["CC-Request-Type"]
        if in_avps_dic.has_key("CC-Request-Number"):
            template_dic["CC-Request-Number"]=in_avps_dic["CC-Request-Number"]
        if in_avps_dic.has_key("Destination-Host"):
            template_dic["Origin-Host"]=in_avps_dic["Destination-Host"]
        if in_avps_dic.has_key("Destination-Realm"):
            template_dic["Origin-Realm"]=in_avps_dic["Destination-Realm"]
        if in_avps_dic.has_key("Origin-Host"):
            template_dic["Destination-Host"]=in_avps_dic["Origin-Host"]
        if in_avps_dic.has_key("Origin-Realm"):
            template_dic["Destination-Realm"]=in_avps_dic["Origin-Realm"]
        if msg_type=="CCA":
            pass
        elif msg_type=="TSA":
            pass
        elif msg_type=="RAA":
            pass
        return template_dic