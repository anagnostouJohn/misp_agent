#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  6 13:33:05 2018

@author: john
"""

# Python program to implement server side of chat room.
import socket
import ssl
import os
import threading 
import json
from diffiehellman.diffiehellman import DiffieHellman

KEYFILE = os.getcwd()+'/certs/key.pem'
CERTFILE = os.getcwd()+'/certs/cert.pem'
alice = DiffieHellman()
Port = 8202
IP_address = '192.168.168.184'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((IP_address, Port))
server = ssl.wrap_socket(server, keyfile=KEYFILE, certfile=CERTFILE, server_side=True)
server.listen()

def clientthread(conn,addr):
    alice.generate_public_key()
    total_data = ""
    while True:
        try:
            conn.settimeout(1)
            #print("..")
            message = ""
            message = conn.recv(100)
            while message is not "":                
                total_data+=message.decode("utf-8")
                message = "" 
                message = conn.recv(100)
            else:
                break
        except socket.error as ex:
            print(ex)
        x = {"alice":alice.public_key}
        conn.send(json.dumps(x).encode("utf-8"))
        f = json.loads(total_data)
        alice.generate_shared_secret(f["bob"], echo_return_key=True)
        print (alice.shared_key)
        print("END")
        break

while True :
    try:
        server.settimeout(1)
        conn, addr = server.accept()
        print("EDO")
        t1 = threading.Thread(target = clientthread, args = (conn,addr)) 
        t1.start()
    except socket.error as e:
        print(e)
