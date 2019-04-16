#!/usr/bin/env python
#coding=utf-8

import socket
import select
import sctp


# Open a SCTP sock as One-to-Many SCTP
s = sctp.sctpsocket_tcp(socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 3868))
s.listen(5)


while 1:
    in_fds,out_fds,err_fds = select.select([s,],[],[],3)
    if len(in_fds) != 0:
        server_sock,client_address=s.accept()
        print server_sock.recv(1000)

