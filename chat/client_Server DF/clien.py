#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  6 13:34:29 2018

@author: john
"""
import socket
import os
import ssl
import json
from diffiehellman.diffiehellman import DiffieHellman

CERT = os.getcwd()+'/certs/cert.pem'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server = ssl.wrap_socket(server,cert_reqs=ssl.CERT_REQUIRED, ca_certs = CERT)
server.settimeout(5)



IP_address = '192.168.168.184'
Port = 8202
server.connect((IP_address, Port))
bob = DiffieHellman()
bob.generate_public_key()
x = {"bob":bob.public_key}
server.send(json.dumps(x).encode("utf-8"))
total_data=""
# ########################################## REC #############################################
while True:
    try:        
        message = ""
        message = server.recv(100)
        while message is not "":             
            total_data+=message.decode("utf-8")
            message = "" 
            message = server.recv(100)
        else:
            break
    except socket.error as ex:
        print(ex)
        break
# ########################################## REC #############################################
f= json.loads(total_data)
bob.generate_shared_secret(f["alice"], echo_return_key=True)
print(bob.shared_key)

