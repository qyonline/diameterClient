#!/usr/bin/env python
#coding=utf-8

import os,logging,smtplib,ConfigParser,zipfile
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
from logging.handlers import TimedRotatingFileHandler
import traceback

class SearchFile:
    "Search file by special file suffix or file prefix"
    global filenamelist
    filenamelist=[]
    def __init__(self):
        pass
        #self.filenamelist=[]
        
    def visit(self,arg,dirname,names,flist=filenamelist):
        #flist=self.filenamelist
        flist += [dirname + os.sep + file for file in names]

    def get_files_by_suffix(self,dictory,suffix):
        '''
        *******************************************************************************
        *  Fucntion description: get file full path by suffix.
        *  Input paramater:
        *  Dictory: the root directory which is searhc
        *  suffix:  file suffix
        *  Output:  File full path list
        *  Author: Jim.yin@aicent.com
        *  Date:  2009.1.22
        *******************************************************************************
        '''
        scriptfilelist=[]
        os.path.walk(dictory, self.visit, 0)
        for script in filenamelist:
            if script.endswith(suffix) and os.path.isfile(script):
                scriptfilelist.append(script)
            else:
                pass
        #For filenamelist is global variable,if we use the multi method in this class
        #the filenamelist list include all search result, so we should empty it.
        del filenamelist[:]
        return scriptfilelist

    def get_files_by_prefix(self,dictory,prefix):
        scriptfilelist=[]
        os.path.walk(dictory, self.visit, 0)
        for script in filenamelist:
            if os.path.basename(script).startswith(prefix) and os.path.isfile(script):
                scriptfilelist.append(script)
            else:
                pass
        del filenamelist[:]
        return scriptfilelist
    
    def get_match_dir(self,dictory,dir_name):
        '''
        *******************************************************************************
        *  Fucntion description: get extra directory full path
        *  Input paramater: dir_name 
        *  Dictory: the root directory which is searhc
        *  suffix:  file suffix
        *  Output:  dir full path list
        *  Author: Jim.yin@aicent.com
        *  Date:  2009.3.25
        *******************************************************************************        
        '''
        match_dir_path=[]
        os.path.walk(dictory, self.visit, 0)
        for dir in filenamelist:
            if os.path.isdir(dir) and os.path.basename(dir)==dir_name:
                match_dir_path.append(dir)
            else:
                pass
        del filenamelist[:]
        return match_dir_path
    
    def get_dirs_by_prefix(self,dictory,prefix):
        dir_list=[]
        os.path.walk(dictory, self.visit, 0)
        for dir in filenamelist:
            if os.path.basename(dir).startswith(prefix) and os.path.isdir(dir):
                dir_list.append(dir)
            else:
                pass
        del filenamelist[:]
        return dir_list

class ConfigFile:

    def init_attri_config_file(self,finename):
        '''
        Use ConfigParser to parse below configuration file:
        [selection]:
        option:value
        '''
        config = ConfigParser.ConfigParser()


        try:
            if os.path.isfile(finename):
                config.read(finename)
                return config
            else:
                print finename,"not exist"
        except ConfigParser.ParsingError:
            traceback.print_exc()

'''
*******************************************************************************
*  Fucntion description: define log input obejct and log format
*  Input paramater: N/A
*  Output: loger instance
*  Author: Jim.yin@aicent.com
*  Date:  2007.12.6
*******************************************************************************
'''

def send_mail(fro,to, subject, text, files='',server="localhost"):
    to=to.split(",")
    msg = MIMEMultipart()
    msg['From'] = fro
    msg['To'] = ";".join(to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach( MIMEText(text) )
    files=files.split(',')
    for file in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(file,"rb").read() )
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"'
                       % os.path.basename(file))
        msg.attach(part)

    smtp = smtplib.SMTP(server)
    smtp.sendmail(fro, to, msg.as_string() )
    smtp.close()

def init_log(log_level,logpath):
    '''
    logger = logging.getLogger()
    hdlr = logging.FileHandler(logpath)
    formatter = logging.Formatter('%(asctime)s -8s thread-%(thread)[%(levelname)-8s %(module)s:%(lineno)d] %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(log_level)

    return logger
    '''
    logger = logging.getLogger()
    hdlr =TimedRotatingFileHandler(logpath,"D", 1, 10)
    hdlr.suffix = "%Y%m%d" 
    #formatter = logging.Formatter('%(asctime)s -8s thread-%(thread)[%(levelname)-8s %(module)s:%(lineno)d] %(message)s')
    formatter = logging.Formatter('%(asctime)s [%(levelname)-8s Thread: %(threadName)s: %(module)s:%(lineno)d] %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(log_level)

    return logger

class ZipOperate:
    '''
    zip folder foldername and all its subfiles and folders into
    a zipfile named filename
    '''
    def __init__(self):
        pass
    
    def zipfolder(self,foldername,filename):
        '''
        The foldername could not end with os seprate charactor,
        for example:D:\\work\\TestScript\\SVN\\MMVD\\trunk\\mat\\conf\\mmsfile\\
        could not work
        it should be D:\\work\\TestScript\\SVN\\MMVD\\trunk\\mat\\conf\\mmsfile
        '''
        cwd=os.getcwd()
        folder=os.path.basename(foldername)
        folder_path=os.path.dirname(foldername)
        os.chdir(folder_path)
        
        empty_dirs=[]
        zip=zipfile.ZipFile(filename,'w',zipfile.ZIP_DEFLATED)
        for root,dirs,files in os.walk(folder):
            empty_dirs.extend([dir for dir in dirs if os.listdir(os.path.join(root,dir))==[]])
            for filename in files:
                zip.write(os.path.join(root,filename))
        for dir in empty_dirs:
            zif=zipfile.ZipInfo(os.path.join(root,dir))
            zip.writestr(zif,"")
        zip.close()
        os.chdir(cwd)
    #unzip http://www.devshed.com/c/a/Python/Python-UnZipped/1/

if __name__=="__main__":
    '''
    sf=SearchFile()
    sf.get_files_by_suffix('../../conf/simulator1','properties')
    sf.get_files_by_suffix('../../conf/simulator2','properties')
    print sf.get_match_dir('../caseslib','test_1_10')
    cf=ConfigFile()
    dic=cf.init_attri_config_file(r'D:\work\TestScript\SVN\GMD\trunk\gat\src\caseslib\cimd\test_5_1\caseattribute.cfg')
    print dic.defaults()
    '''

    cf=ConfigFile()
    gat_prop=cf.init_attri_config_file("D:\jobs\code\TestScript\SVN\TCPPeering\conf\peeringtcp.cfg")
    gat_prop.get('sysparm',"log_level")

    #print os.path.isfile("D:\jobs\code\TestScript\SVN\TCPPeering\conf\peeringtcp.cfg")


