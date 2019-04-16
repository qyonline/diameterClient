#!/usr/bin/evn python
#coding=utf-8

import socket
import select
import sctp
import sys



sk = sctp.sctpsocket_tcp(socket.AF_INET)
sk.connect((socket.gethostbyname(socket.gethostname()), 3868))
sk.sctp_send("test jim")
sk.close()

