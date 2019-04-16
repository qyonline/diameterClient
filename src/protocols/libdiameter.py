#!/usr/bin/env python
#coding=utf-8
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - Nov 2012
# Version 0.3.1, Last change on Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode diameter messages

import xml.dom.minidom as minidom
import struct
import codecs
import socket
import sys
import logging
import time
import datetime
import  random
import  os
import  traceback
from aicent import configobj

# Diameter Header fields

DIAMETER_FLAG_MANDATORY = 0x40
DIAMETER_FLAG_VENDOR    = 0x80

DIAMETER_HDR_REQUEST    = 0x80
DIAMETER_HDR_PROXIABLE  = 0x40
DIAMETER_HDR_ERROR      = 0x20
DIAMETER_HDR_RETRANSMIT = 0x10

# Include common routines for all modules
ERROR = -1

MSG_TERM={"ULR":"3GPP-Update-Location","ULA":"3GPP-Update-Location",
          "CLR":"3GPP-Cancel-Location","CLA":"3GPP-Cancel-Location",
          "AIR":"3GPP-Authentication-Information","AIA":"3GPP-Authentication-Information",
          "IDR":"3GPP-Insert-Subscriber-Data","IDA":"3GPP-Insert-Subscriber-Data",
          "DSR":"3GPP-Delete-Subscriber-Data","DSA":"3GPP-Delete-Subscriber-Data",
          "PUR":"3GPP-Purge-UE","PUA":"3GPP-Purge-UE",
          "RSR":"3GPP-Reset","RSA":"3GPP-Reset",
          "NOR":"3GPP-Notify","NOA":"3GPP-Notify",
          "CCR":"Credit-Control","CCA":"Credit-Control",
          "TSR":"TDF-Session-Request","TSA":"TDF-Session-Request",
          "RAR":"Re-Auth","RAA":"Re-Auth",
          "DWR":"Device-Watchdog","DWA":"Device-Watchdog"}
APPID=0

def avps_value_dic(msg_type,diameter_cfg="../conf/diameter.cfg"):
    diameter_cfg=configobj.ConfigObj(diameter_cfg)
    msg_paras_dic={}

    for option in diameter_cfg[msg_type].keys():
        if "}" in diameter_cfg[msg_type][option]:
            msg_paras_dic[option]=eval(diameter_cfg[msg_type][option])

        elif option=="Session-Id" and "<" in diameter_cfg[msg_type][option]:
            if "User-Name" in diameter_cfg[msg_type].keys():
                    session_id=create_Session_Id(diameter_cfg[msg_type]["Origin-Host"],diameter_cfg[msg_type]["User-Name"])
            else:
                    session_id=create_Session_Id(diameter_cfg[msg_type]["Origin-Host"],str(random.randrange(200000000000000)))
            msg_paras_dic[option]=session_id
        else:
            msg_paras_dic[option]=diameter_cfg[msg_type][option]
    return  msg_paras_dic

def set_avps_value(new_avp_dic,complete_avps_dic):
    for k,v in new_avp_dic.iteritems():
        complete_avps_dic[k]=v
    return complete_avps_dic

# Hopefully let's keep dictionary definition compatibile
class AVPItem:
    def __init__(self):
        self.code=0
        self.name=""
        self.vendor=0
        self.type=""
        self.mandatory=""
        
class HDRItem:
    def __init__(self):
        self.ver=0
        self.flags=0
        self.len=0
        self.cmd=0
        self.appId=0
        #self.HobByHop=0
        self.HopByHop=0
        self.EndToEnd=0
        self.msg=""
    
#----------------------------------------------------------------------

utf8encoder=codecs.getencoder("utf_8")
utf8decoder=codecs.getdecoder("utf_8")

#----------------------------------------------------------------------
# Dictionary routines

# Load simplified dictionary from <file>
def LoadDictionary(file):
    global dict_avps
    global dict_vendors
    global dict_commands
    global asString
    global asUTF8
    global asU32
    global asI32
    global asU64
    global asI64
    global asF32
    global asF64
    global asIPAddress
    global asIP
    global asTime
    doc = minidom.parse(file)
    node = doc.documentElement
    dict_avps = doc.getElementsByTagName("avp")
    dict_vendors = doc.getElementsByTagName("vendor")
    dict_commands=doc.getElementsByTagName("command")
    # Now lets process typedefs
    asString=["OctetString"]
    asUTF8=["UTF8String"]
    asI32=["Integer32"]
    asU32=["Unsigned32"]
    asF32=["Float32"]
    asI64=["Integer64"]
    asU64=["Unsigned64"]
    asF64=["Float64"]
    asIPAddress=["IPAddress"]
    asIP=["IP"]    
    asTime=["Time"]    
    dict_typedefs=doc.getElementsByTagName("typedef")
    for td in dict_typedefs:
        tName=td.getAttribute("name")
        tType=td.getAttribute("type")
        if tType in asString:
           asString.append(tName)
        if tType in asUTF8:
           asUTF8.append(tName)
        if tType in asU32:
           asU32.append(tName)
        if tType in asI32:
           asI32.append(tName)
        if tType in asI64:
           asI64.append(tName)    
        if tType in asU64:
           asU64.append(tName)           
        if tType in asF32:
           asF32.append(tName)           
        if tType in asF64:
           asF64.append(tName)           
        if tType in asIPAddress:
           asIPAddress.append(tName)
        if tType in asIP:
           asIP.append(tName)           
        if tType in asTime:
           asTime.append(tName)   
        
# Find AVP definition in dictionary: User-Name->1
# on finish A contains all data
def dictAVPname2code(A,avpname,avpvalue):
    global dict_avps
    dbg="Searching dictionary for Name:",avpname,"Value:",avpvalue
    logging.debug(dbg)
    for avp in dict_avps:
        A.name = avp.getAttribute("name")
        A.code = avp.getAttribute("code")
        A.mandatory=avp.getAttribute("mandatory")
        A.type = avp.getAttribute("type")
        vId = avp.getAttribute("vendor-id")
        if avpname==A.name:
           if vId=="":
                A.vendor=0
           else:
                A.vendor=dictVENDORid2code(vId)
           return
    dbg="Searching dictionary failed for Name",avpname,"Value",avpvalue
    bailOut(dbg)

# Find AVP definition in dictionary: 1->User-Name
# on finish A contains all data
def dictAVPcode2name(A,avpcode,vendorcode):
    global dict_avps
    dbg="Searching dictionary for ","avp code:",avpcode,"Vendor code:",vendorcode
    logging.debug(dbg)
    A.vendor=dictVENDORcode2id(int(vendorcode))
    for avp in dict_avps:
        A.name = avp.getAttribute("name")
        A.type = avp.getAttribute("type")
        try:
            A.code = int(avp.getAttribute("code"))
        except ValueError:
            logging.debug("##name:"+A.name)
            logging.error(traceback.print_exc())
        A.mandatory=avp.getAttribute("mandatory")
        vId = avp.getAttribute("vendor-id")
        if int(avpcode)==A.code:
            if vId=="":
               vId="None"
            if vId==A.vendor:
               return
    logging.debug("Unsuccessful search")
    A.code=avpcode
    A.name="Unknown Attr-"+str(A.code)+" (Vendor:"+A.vendor+")"
    A.type="OctetString"
    return

# Find Vendor definition in dictionary: 10415->TGPP    
def dictVENDORcode2id(code):
    global dict_vendors
    dbg="Searching Vendor dictionary for Code:",code
    logging.debug(dbg)
    #logging.debug("code type:"+str(type(code)))
    for vendor in dict_vendors:
        vCode=vendor.getAttribute("code")
        vId=vendor.getAttribute("vendor-id")
        if code==int(vCode):
            return vId
    dbg="Searching Vendor dictionary failed for C",code
    bailOut(dbg)

# Find Vendor definition in dictionary: TGPP->10415    
def dictVENDORid2code(vendor_id):
    global dict_vendors
    dbg="Searching Vendor dictionary for Value",vendor_id
    logging.debug(dbg)
    for vendor in dict_vendors:
        Code=vendor.getAttribute("code")
        vId=vendor.getAttribute("vendor-id")
        if vendor_id==vId:
            return int(Code)
    dbg="Searching Vendor dictionary failed for Value",vendor_id
    bailOut(dbg)

# Find Command definition in dictionary: Capabilities-Exchange->257    
def dictCOMMANDname2code(name):
    global dict_commands
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=command.getAttribute("code")
         if cName==name:
            return int(cCode)
    dbg="Searching CMD dictionary failed for N",name
    bailOut(dbg)

# Find Command definition in dictionary: 257->Capabilities-Exchange
def dictCOMMANDcode2name(flags,code):
    global dict_commands
    cmd=ERROR
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=command.getAttribute("code")
         if code==int(cCode):
            cmd=cName
    if cmd==ERROR:
        return cmd
    if flags&DIAMETER_HDR_REQUEST==DIAMETER_HDR_REQUEST:
        dbg=cmd+" Request"
    else:
        dbg=cmd+" Answer"
    return dbg

#----------------------------------------------------------------------
# These are defined on Unix python.socket, but not on Windows
# Pack/Unpack IP address
def inet_pton(address_family, ip_string): 
    #Convert an IP address from text represenation to binary form
    if address_family == socket.AF_INET:
        return socket.inet_aton(ip_string)
    elif address_family == socket.AF_INET6:
        # IPv6: The use of "::" indicates one or more groups of 16 bits of zeros.
        # We deal with this form of wildcard using a special marker. 
        JOKER = "*"
        while "::" in ip_string:
            ip_string = ip_string.replace("::", ":" + JOKER + ":")
        joker_pos = None
        # The last part of an IPv6 address can be an IPv4 address
        ipv4_addr = None
        if "." in ip_string:
            ipv4_addr = ip_string.split(":")[-1]
        result = ""
        parts = ip_string.split(":")
        for part in parts:
            if part == JOKER:
                # Wildcard is only allowed once
                if joker_pos is None:
                   joker_pos = len(result)
                else:
                   bailOut("Illegal syntax for IP address")
            elif part == ipv4_addr:
                # FIXME: Make sure IPv4 can only be last part
                # FIXME: inet_aton allows IPv4 addresses with less than 4 octets 
                result += socket.inet_aton(ipv4_addr)
            else:
                # Each part must be 16bit. Add missing zeroes before decoding. 
                try:
                    result += part.rjust(4, "0").decode("hex")
                except TypeError:
                    bailOut("Illegal syntax for IP address")
        # If there's a wildcard, fill up with zeros to reach 128bit (16 bytes) 
        if JOKER in ip_string:
            result = (result[:joker_pos] + "\x00" * (16 - len(result))
                      + result[joker_pos:])
        if len(result) != 16:
            bailOut("Illegal syntax for IP address")
        return result
    else:
        bailOut("Address family not supported")

def inet_ntop(address_family, packed_ip): 
    #Convert an IP address from binary form into text represenation
    if address_family == socket.AF_INET:
        #return socket.inet_ntoa(packed_ip)
        try:
            pack=int(packed_ip,16)
            return socket.inet_ntoa(struct.pack(">L",pack))
        except:
            return  "Parse Error"

        #return socket.inet_ntoa(struct.pack(">L", int(packed_ip,16)))
    elif address_family == socket.AF_INET6:
        # IPv6 addresses have 128bits (16 bytes)
        if len(packed_ip) != 16:
            bailOut("Illegal syntax for IP address")
        parts = []
        for left in [0, 2, 4, 6, 8, 10, 12, 14]:
            try:
                value = struct.unpack("!H", packed_ip[left:left+2])[0]
                hexstr = hex(value)[2:]
            except TypeError:
                bailOut("Illegal syntax for IP address")
            parts.append(hexstr.lstrip("0").lower())
        result = ":".join(parts)
        while ":::" in result:
            result = result.replace(":::", "::")
        # Leaving out leading and trailing zeros is only allowed with ::
        if result.endswith(":") and not result.endswith("::"):
            result = result + "0"
        if result.startswith(":") and not result.startswith("::"):
            result = "0" + result
        return result
    else:
        bailOut("Address family not supported yet")

#Pack IP address  
def pack_address(address):
    # This has issue on Windows platform
    # addrs=socket.getaddrinfo(address, None)
    # This is NOT a proper code, but it will do for now
    # unfortunately, getaddrinfo does not work on windows with IPv6
    if address.find('.')!=ERROR:
        '''
        raw = inet_pton(socket.AF_INET,address);
        d=struct.pack('!h4s',1,raw)
        '''
        d=socket.inet_aton(address)
        return d
    if address.find(':')!=ERROR:
        raw = inet_pton(socket.AF_INET6,address);
        d=struct.pack('16s',raw)
        return d
    dbg='Malformed IP'
    bailOut(dbg)

#----------------------------------------------------------------------
#
# Decoding section
#

def decode_Integer32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)

def decode_Integer64(data):
    ret=struct.unpack("!Q",data.decode("hex"))[0]
    return int(ret)
  
def decode_Unsigned32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)
  
def decode_Unsigned64(data):
    ret=struct.unpack("!Q",data.decode("hex"))[0]
    return int(ret)

def decode_Float32(data):
    ret=struct.unpack("!f",data.decode("hex"))[0]
    return ret

def decode_Float64(data):
    ret=struct.unpack("!d",data.decode("hex"))[0]
    return ret
    
def decode_Address(data):
    #Add to handle exceptional address encode,jim.yin
    #data="0001"+data
    if len(data)<=16:
        #data=data[4:12]
        #ret=inet_ntop(socket.AF_INET,data.decode("hex"))
        ret=inet_ntop(socket.AF_INET,data)
    else:
        data=data[4:36]    
        ret=inet_ntop(socket.AF_INET6,data.decode("hex"))
    return ret

def decode_IP(data):
    if len(data)<=16:
        #ret=inet_ntop(socket.AF_INET,data.decode("hex"))
        ret=inet_ntop(socket.AF_INET,data)
    else:
        ret=inet_ntop(socket.AF_INET6,data.decode("hex"))
    return ret
    
def decode_OctetString(data,dlen):
    fs="!"+str(dlen-8)+"s"
    #dbg="Deconding String with format:",fs
    #logging.debug(dbg)
    ret=struct.unpack(fs,data.decode("hex")[0:dlen-8])[0]
    return ret

#Hex          Comments
#0x00..0x7F   Only byte of a 1-byte character encoding
#0x80..0xBF   Continuation characters (1-3 continuation characters)
#0xC0..0xDF   First byte of a 2-byte character encoding
#0xE0..0xEF   First byte of a 3-byte character encoding
#0xF0..0xF4   First byte of a 4-byte character encoding
#Note:0xF5-0xFF cannot occur    
def decode_UTF8String(data,dlen):
    fs="!"+str(dlen-8)+"s"
    dbg="Decoding UTF8 format:",fs
    logging.debug(dbg)
    ret=struct.unpack(fs,data.decode("hex")[0:dlen-8])[0]
    utf8=utf8decoder(ret)
    return utf8[0]

def decode_Grouped(data):
    dbg="Decoding Grouped:"
    ret=[]
    for gmsg in splitMsgAVPs(data):
        ret.append(decodeAVP(gmsg))
    return ret

#AVP_Time contains a second count since 1900    
def decode_Time(data):
    seconds_between_1900_and_1970 = ((70*365)+17)*86400
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)-seconds_between_1900_and_1970
    
#----------------------------------------------------------------------
    
# Quit program with error
def bailOut(msg):
    logging.error(msg)
    sys.exit(1)
    
#Split message into parts (remove field from remaining body)
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])
    
#----------------------------------------------------------------------    

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                           AVP Code                            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |V M P r r r r r|                  AVP Length                   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        Vendor-ID (opt)                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Data ...
#   +-+-+-+-+-+-+-+-+

# Common finish routine for all encoded AVPs
# Result is properly encoded AVP as hex string (padding is added separately)
def encode_finish(A,flags,pktlen,data):
    ret=data
    if A.vendor!=0:
       ret=("%08X" % int(A.vendor)) + ret
       flags|=DIAMETER_FLAG_VENDOR
       pktlen+=4
    dbg="Packing","Code:",A.code,"Flags:",flags,"Vendor:",A.vendor,"Length:",pktlen,"Data:",ret
    logging.debug(dbg)
    ret=("%08X"%int(A.code))+("%02X"%int(flags))+("%06X"%pktlen)+ret
    return ret

def reversal(data):
    new_data=""
    data_list=list(data)
    while data_list:
        if len(data_list)>1:
            new_data+=(data_list.pop(1)+data_list.pop(0))
        else:
            new_data+=data_list.pop()
    return new_data

def str_to_tbcd(t_str):
    tbcd_c = ['0000', '0001', '0010', '0011', '0100', '0101', '0110',
              '0111', '1000', '1001', '1010', '1011', '1101', '1110' ,'1111']
    tbcd_ascii = "0123456789*#abc"
    s = []
    for i in range(0,len(t_str)+1,2):
        if i<len(t_str):
            if i+2>len(t_str) and i<len(t_str):
                s.append(str(int("0000"+tbcd_c[tbcd_ascii.index(t_str[i])],2)))
            else:
                s.append(str(int(tbcd_c[tbcd_ascii.index(t_str[i])]+tbcd_c[tbcd_ascii.index(t_str[i+1])],2)))
    return (''.join(s)).encode("hex")
    
def encode_OctetString(A,flags,data):
    number_list=["Visited-PLMN-Id","3GPP-MSISDN"]
    fs="!"+str(len(data))+"s"
    #dbg="Encoding String format:",fs
    #logging.debug(dbg)
    if A.name in number_list:
        ret=reversal(data)
    elif A.name=="STN-SR":
        #ret=str_to_tbcd(data)
        ret=data
    else:
        ret=struct.pack(fs,data).encode("hex")
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)

def encode_UTF8String(A,flags,data):
    #print A,flags,data
    utf8data=utf8encoder(data)[0]
    fs="!"+str(len(utf8data))+"s"
    dbg="Encoding UTF8",utf8data,"L",len(utf8data),"F",fs
    logging.debug(dbg)
    ret=struct.pack(fs,utf8data).encode("hex")
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)
    
def encode_Integer32(A,flags,data):
    r=struct.pack("!I",data)
    ret=r.encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)

def encode_Unsigned32(A,flags,data):
    r=struct.pack("!I",int(data))
    ret=r.encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)

def encode_Float32(A,flags,data):
    ret=struct.pack("!f",data).encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)
    
def encode_Integer64(A,flags,data):
    ret=struct.pack("!Q",data).encode("hex")
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Unsigned64(A,flags,data):
    data=long(data)
    ret=struct.pack("!Q",data).encode("hex")
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Float64(A,flags,data):
    ret=struct.pack("!d",data).encode("hex")
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Address(A,flags,data):
    if data.find('.')!=ERROR:
        #remove redundant 2 byte for IPV4
        #ret=pack_address(data).encode("hex")[4:]
        ret=pack_address(data).encode("hex")
    if data.find(':')!=ERROR:
        ret=pack_address(data).encode("hex")
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)
    
def encode_IP(A,flags,data):
    if data.find('.')!=ERROR:
        ret=pack_address(data).encode("hex")
    if data.find(':')!=ERROR:
        ret=pack_address(data).encode("hex")
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)    

def encode_Enumerated(A,flags,data):
    global dict_avps
    if isinstance(data,str):
        # Replace with enum code value
        for avp in dict_avps:
            Name = avp.getAttribute("name")
            if Name==A.name:
                for e in avp.getElementsByTagName("enum"):
                    if data==e.getAttribute("name"):
                        return encode_Integer32(A,flags,int(e.getAttribute("code")))
                dbg="Enum name=",data,"not found for AVP",A.name
                bailOut(dbg)
    else:
        return encode_Integer32(A,flags,data)
    
#AVP_Time contains a second count since 1900    
#But unix counts time from EPOCH (1.1.1970)
def encode_Time(A,flags,data):
    #logging.debug("flags and data:"+flags,data)
    seconds_between_1900_and_1970 = ((70*365)+17)*86400 
    r=struct.pack("!I",int(data)+seconds_between_1900_and_1970)
    ret=r.encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)

#----------------------------------------------------------------------     
#Set mandatory flag as specified in dictionary
def checkMandatory(mandatory):
    flags=0
    if mandatory=="must":
        flags|=DIAMETER_FLAG_MANDATORY
    return flags
    
def do_encode(A,flags,data):
    if A.type in asUTF8:
        return encode_UTF8String(A,flags,data)
    if A.type in asI32:
        return encode_Integer32(A,flags,data)
    if A.type in asU32:
        return encode_Unsigned32(A,flags,data)
    if A.type in asI64:
        return encode_Integer64(A,flags,data)
    if A.type in asU64:
        return encode_Unsigned64(A,flags,data)
    if A.type in asF32:
        return encode_Float32(A,flags,data)
    if A.type in asF64:
        return encode_Float64(A,flags,data)
    if A.type in asIPAddress:
        return encode_Address(A,flags,data)
    if A.type in asIP:
        return encode_IP(A,flags,data)        
    if A.type in asTime:
        return encode_Time(A,flags,data)
    if A.type=="Enumerated":
        return encode_Enumerated(A,flags,data)
    # default is OctetString  
    return encode_OctetString(A,flags,data) 

# Find AVP Definition in dictionary and encode it
def getAVPDef(AVP_Name,AVP_Value):
    A=AVPItem()
    dictAVPname2code(A,AVP_Name,AVP_Value)
    if A.name=="":
       logging.error("AVP with that name not found")
       return ""
    if A.code==0:
       logging.error("AVP Code not found")
       return ""
    if A.type=="":
       logging.error("AVP type not defined")
       return ""
    if A.vendor<0:
       logging.error("Vendor ID does not match")
       return ""
    else:
        data=AVP_Value
    dbg="AVP dictionary def","Name",A.name,"Code",A.code,"M",A.mandatory,"Type",A.type,"Vendor",A.vendor,"value",data
    logging.debug(dbg)
    flags=checkMandatory(A.mandatory)
    return do_encode(A,flags,data)

################################
# Main encoding routine  
def encodeAVP(AVP_Name,AVP_Value):
    #the Grouped type's AVP_Value is list
    if type(AVP_Value).__name__=='list':
        p=''
        for x in AVP_Value:
            while len(x)/2<calc_padding(len(x)/2):
                x=x+'00'
            p=p+x
        msg=getAVPDef(AVP_Name,p.decode("hex"))
    else:
        msg=getAVPDef(AVP_Name,AVP_Value)
    dbg="AVP",AVP_Name,AVP_Value,"Encoded as:",msg
    logging.debug(dbg)
    return msg

# Calculate message padding
def calc_padding(msg_len):
    return (msg_len+3)&~3 

#----------------------------------------------------------------------    
################################
# Main decoding routine  
# Input: single AVP as HEX string
def decodeAVP(msg):
    (scode,msg)=chop_msg(msg,8)
    (sflag,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,6)
    dbg="Decoding ","C",scode,"F",sflag,"L",slen,"D",msg
    logging.debug(dbg)
    mcode=struct.unpack("!I",scode.decode("hex"))[0]
    mflags=ord(sflag.decode("hex"))
    data_len=struct.unpack("!I","\00"+slen.decode("hex"))[0]
    mvid=0
    if mflags & DIAMETER_FLAG_VENDOR:
        (svid,msg)=chop_msg(msg,8)
        mvid=struct.unpack("!I",svid.decode("hex"))[0]
        data_len-=4
    A=AVPItem()
    dictAVPcode2name(A,mcode,mvid)
    dbg="Read","N",A.name,"T",A.type,"C",A.code,"F",mflags,"L",data_len,"V",A.vendor,mvid,"D",msg
    logging.debug(dbg)
    ret=""
    decoded=False
    if A.type in asI32:
        #logging.debug("Decoding Integer32")
        ret= decode_Integer32(msg)
        decoded=True
    if A.type in asI64:
        decoded=True
        #logging.debug("Decoding Integer64")
        ret= decode_Integer64(msg)
    if A.type in asU32:
        decoded=True
        #logging.debug("Decoding Unsigned32")
        ret= decode_Unsigned32(msg)
    if A.type in asU64:
        decoded=True
        #logging.debug("Decoding Unsigned64")
        ret= decode_Unsigned64(msg)
    if A.type in asF32:
        decoded=True
        #logging.debug("Decoding Float32")
        ret= decode_Float32(msg)
    if A.type in asF64:
        decoded=True
        #logging.debug("Decoding Float64")
        ret= decode_Float64(msg)        
    if A.type in asUTF8:
        decoded=True
        #logging.debug("Decoding UTF8String")
        ret= decode_UTF8String(msg,data_len)
    if A.type in asIPAddress:
        decoded=True
        #logging.debug("Decoding IPAddress")
        ret= decode_Address(msg)
    if A.type in asIP:
        decoded=True
        #logging.debug("Decoding IP")
        ret= decode_IP(msg)        
    if A.type in asTime:
        decoded=True
        #logging.debug("Decoding Time")
        ret= decode_Time(msg)
    if A.type=="Grouped":
        decoded=True
        #logging.debug("Decoding Grouped")
        ret= decode_Grouped(msg)
    if not decoded:
      # default is OctetString
      #logging.debug("Decoding OctetString")
      ret= decode_OctetString(msg,data_len)
    dbg="Decoded as",A.name,ret
    logging.debug(dbg)
    return (A.name,ret)

# Search for AVP in undecoded list
# Return value if exist, ERROR if not    
def findAVP(what,list):
    for avp in list:
        if isinstance(avp,tuple):
           (Name,Value)=avp
        else:
           (Name,Value)=decodeAVP(avp)
        if Name==what:
           return Value
    return ERROR
    
#---------------------------------------------------------------------- 

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Version    |                 Message Length                |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | command flags |                  Command-Code                 |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                         Application-ID                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Hop-by-Hop Identifier                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      End-to-End Identifier                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  AVPs ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-

# Join AVPs (add padding)
def joinAVPs(avps):
    data=""
    for avp in avps:
        while len(avp)/2<calc_padding(len(avp)/2):
            avp=avp+"00"
        data=data+avp
    return data

# Set flags to desired state    
def setFlags(H,flag):
    H.flags|=flag
    return

# Create diameter Request from <avps> and fields from Header H    
def createReq(H,avps):
    H.flags|=DIAMETER_HDR_REQUEST
    return createRes(H,avps)

# Create diameter Response from <avps> and fields from Header H     
def createRes(H,avps):
    # first add all avps into single string
    data=joinAVPs(avps)
    # since all data is hex ecoded, divide by 2 and add header length
    H.len=len(data)/2+20
    ret="01"+"%06X" % H.len+"%02X"%int(H.flags) + "%06X"%int(H.cmd)
    ret=ret+"%08X"%H.appId+"%08X"%H.HopByHop+ "%08X"%H.EndToEnd+data
    dbg="Header fields","L",H.len,"F",H.flags,"C",H.cmd,"A",H.appId,"H",H.HopByHop,"E",H.EndToEnd
    logging.debug(dbg)
    dbg="Diameter hdr+data",ret
    logging.debug(dbg)
    return ret

# Set Hop-by-Hop and End-to-End fields to sane values    
def initializeHops(H):
    # Not by RFC, but close enough
    try:
        initializeHops.Hop_by_Hop+=1
        initializeHops.End_to_End+=1
    except:
        initializeHops.Hop_by_Hop=int(time.time())
        initializeHops.End_to_End=(initializeHops.Hop_by_Hop%32768)*32768
    H.HopByHop=initializeHops.Hop_by_Hop
    H.EndToEnd=initializeHops.End_to_End
    return 
    
#---------------------------------------------------------------------- 

# Main message decoding routine
# Input: diameter message as HEX string    
# Result: class H with splitted message (header+message)
# AVPs in message are NOT splitted
def stripHdr(H,msg):
    dbg="Incoming Diameter msg",msg
    logging.debug(dbg)
    if len(msg)==0:
        return ERROR
    (sver,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,6)
    (sflag,msg)=chop_msg(msg,2)
    (scode,msg)=chop_msg(msg,6)
    (sapp,msg)=chop_msg(msg,8)
    (shbh,msg)=chop_msg(msg,8)
    (sete,msg)=chop_msg(msg,8)
    dbg="Split hdr","V",sver,"L",slen,"F",sflag,"C",scode,"A",sapp,"H",shbh,"E",sete,"D",msg
    logging.debug(dbg)
    H.ver=ord(sver.decode("hex"))
    H.flags=ord(sflag.decode("hex"))
    H.len=struct.unpack("!I","\00"+slen.decode("hex"))[0]
    H.cmd=struct.unpack("!I","\00"+scode.decode("hex"))[0]
    H.appId=struct.unpack("!I",sapp.decode("hex"))[0]
    H.HopByHop=struct.unpack("!I",shbh.decode("hex"))[0]
    H.EndToEnd=struct.unpack("!I",sete.decode("hex"))[0]
    dbg="Read","V",H.ver,"L",H.len,"F",H.flags,"C",H.cmd,"A",H.appId,"H",H.HopByHop,"E",H.EndToEnd
    logging.debug(dbg)
    dbg=dictCOMMANDcode2name(H.flags,H.cmd)
    logging.debug(dbg)
    H.msg=msg
    return 

# Split AVPs from message
# Input: H.msg as hex string
# Result: list of undecoded AVPs
def splitMsgAVPs(msg):
    ret=[]
    dbg="Incoming avps",msg
    logging.debug(dbg)
    print dbg
    while len(msg)<>0:
      slen="00"+msg[10:16]
      print slen
      mlen=struct.unpack("!I",slen.decode("hex"))[0]
      #Increase to boundary
      plen=calc_padding(mlen)
      (avp,msg)=chop_msg(msg,2*plen)
      #dbg="Single AVP","L",mlen,plen,"D",avp
      #logging.info(dbg)
      ret.append(avp)
    return ret

#---------------------------------------------------------------------- 
 
# Connect to host:port (TCP) 
def Connect(host,port):
    # Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock
    
#---------------------------------------------------------------------- 
# DateTime routines

def getCurrentDateTime():
    t=time.localtime()
    return t.tm_year,t.tm_mon,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec

# converts seconds since epoch to date
def epoch2date(sec):
    t=time.localtime(sec)
    return t.tm_year,t.tm_mon,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec

# converts to seconds since epoch
def date2epoch(tYear,tMon,tDate,tHr,tMin,tSec):  
    t=time.strptime("{0} {1} {2} {3} {4} {5}".format(tYear,tMon,tDate,tHr,tMin,tSec),"%Y %m %d %H %M %S")
    return time.mktime(t)    


def set_grouped_avps(option,avp_dic):
    #dic="{'AMBR':{'Max-Requested-Bandwidth-UL': 28700000,'Max-Requested-Bandwidth-DL': 86000000}}"
    #dic={'3GPP-Charging-Characteristics': '800','AMBR':{'Subscriber-Status': 0,'3GPP-Charging-Characteristics': "800"}}
    #SAA_avps.append(encodeAVP("Vendor-Specific-Application-Id",[encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),encodeAVP("Auth-Application-Id",H.appId)]))
    grouped_list=[]
    for k, v in avp_dic.iteritems():
        if k in ["Vendor-Id"]:
            grouped_list.append(encodeAVP(k,dictVENDORid2code(v)))
            #grouped_list.append(encodeAVP(k,v))
        else:
            if isinstance(v,dict):
                sub_encode_avp=set_grouped_avps(k,v)
                grouped_list.append(sub_encode_avp)
                #for sub_v in set_grouped_avps(k,v):
                #    grouped_list.append(sub_v)
                #grouped_list.append(set_grouped_avps(v))
            else:
                if "," in str(v):
                    for inter_v in v.split(","):
                        grouped_list.append(encodeAVP(k,inter_v))
                else:
                    grouped_list.append(encodeAVP(k,v))

    return  encodeAVP(option,grouped_list)


def setAVPs_by_dic(msg_type,avps_dic,avps):
    for k, v in avps_dic.iteritems():
        if isinstance(v,dict):
            avps.append(set_grouped_avps(k,v))
        elif isinstance(v,list):
            for single_v in v:
                if isinstance(single_v,dict):
                    avps.append(set_grouped_avps(k,single_v))
                else:
                    avps.append(encodeAVP(k,single_v))
        else:
            if k=="Auth-Application-Id":
                avps.append(encodeAVP(k,int(v)))
            else:
                avps.append(encodeAVP(k,v))

def setAVPs(msg_type,conf,avps):
    for option in conf[msg_type].keys():
        if "}" in conf[msg_type][option]:
            #print "jim:",set_grouped_avps(eval(conf[msg_type][option]))
            #avps.append(encodeAVP(option,set_grouped_avps(eval(conf[msg_type][option]))))
            avps.append(set_grouped_avps(option,eval(conf[msg_type][option])))
        else:
            if option=="Session-Id" and "auto" in conf[msg_type][option]:
                '''for some case, we need set define seesion-id value, not get it from request,
                so we need keep auto value to do adjustment later
              '''
                if msg_type.endswith("A"):
                    avps.append(encodeAVP(option,conf[msg_type][option])+str(random.randrange(200000000000000)))
                else:
                    if "User-Name" in conf[msg_type].keys():
                        avps.append(encodeAVP(option,
                            create_Session_Id(conf[msg_type]["Origin-Host"],conf[msg_type]["User-Name"])))
                    else:
                        avps.append(encodeAVP(option,
                            create_Session_Id(conf[msg_type]["Origin-Host"],str(random.randrange(200000000000000)))))

            else:

                if isinstance(conf[msg_type][option],list):
                    for single_avp in conf[msg_type][option]:
                        #such configuration:Proxy-Info:"{'Proxy-Host':'nxa.3gppnetwork.com','Proxy-State':'1245853452'}","{'Proxy-Host':'nxa.gppnetwork.com','Proxy-State':'45853452'}"
                        if "}" in single_avp:
                            avps.append(set_grouped_avps(option,eval(single_avp)))
                        else:
                            avps.append(encodeAVP(option,single_avp))
                else:
                    if option=="Auth-Application-Id":
                        avps.append(encodeAVP(option,int(conf[msg_type][option])))
                    else:
                        avps.append(encodeAVP(option,conf[msg_type][option]))


def create_Session_Id(origin_host,user_name):
    #The Session-Id MUST be globally and eternally unique
    #<DiameterIdentity>;<high 32 bits>;<low 32 bits>[;<optional value>]
    now=datetime.datetime.now()
    ret=origin_host+";"
    ret=ret+str(now.year)[2:4]+"%02d"%now.month+"%02d"%now.day
    ret=ret+"%02d"%now.hour+"%02d"%now.minute+";"
    ret=ret+"%02d"%now.second+str(now.microsecond)+";"
    ret=ret+user_name[2:]
    return ret

def create_msg(msg_type,H,diameter_msg_para):
    ULR_avps=[]
    ULR=HDRItem()
    ULR.cmd=dictCOMMANDname2code(MSG_TERM[msg_type])
    if isinstance(diameter_msg_para,dict):
        setAVPs_by_dic(msg_type,diameter_msg_para,ULR_avps)
        ULR.appId=H.appId
        ULR.EndToEnd=H.EndToEnd
        ULR.HopByHop=H.HopByHop
    else:
        logging.debug("Create message by configuration file")
        diameter_cfg_file=configobj.ConfigObj(diameter_msg_para)
        setAVPs(msg_type,diameter_cfg_file,ULR_avps)
        ULR.appId=APPID
        initializeHops(ULR)


    if msg_type.endswith("A"):
        msg=createRes(ULR,ULR_avps)
    else:
        msg=createReq(ULR,ULR_avps)
    return msg

if __name__=="__main__":
    import sys
    sys.path.append(r"D:\bk\branch\diameter4RCC\src")
    reload(sys)
    msg="00000107400000386173633131353b313330393133313030393b34333431313938343b323437303837393436343339390000000000000000000001084000000e617363313135000000000128400000166173632e616963656e742e636f6d00000000010c4000000c000007d001000204c000011001000057000000000000000000000107400000386173633131353b313330393133313030393b34333431313938343b323437303837393436343339390000000000000000000001024000000c01000057000001084000000e6170753030310000000001284000000e61707530303100000000011b400000166173632e616963656e742e636f6d0000000001a04000000c000000020000019f4000000c00000259000001254000000e61736331313500000000042b80000094000028af000003f08000001000007530000000000000042a8000001c000028af313133373837393035333234343630320000042c80000010000028af00000000000001be40000038000001a54000001000000000000000000000019c4000001000000000000000000000019e400000100000000000000000000003ee800000140000753000000000000000000000042b80000094000028af000003f08000001000007530000000020000042a8000001c000028af313133373837393035333234343630320000042c80000010000028af00000000000001be40000038000001a54000001000000000000000000000019c4000001000000000000000000000019e400000100000000000000000000003ee80000014000075300000000000000000000003ed800000100000753074657374000003ee80000014000075300004e63a4ac513b1"
    splitMsgAVPs(msg)
