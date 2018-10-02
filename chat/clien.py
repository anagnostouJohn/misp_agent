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
import hashlib
import time
hash_256 = hashlib.sha256()


bob = DiffieHellman()
CERT = os.getcwd()+'/certs/cert.pem'
IP_address = '192.168.1.3'
Port = 8210
def socket_cr():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #server = ssl.wrap_socket(server,cert_reqs=ssl.CERT_REQUIRED, ca_certs = CERT)
        server.settimeout(3)
        return server
    except socket.error as err :
        print ("Socket Error :", err)



def receive(server):
# ########################################## REC #############################################

    total_data=""
    message = ""
    while True:
        try:
            message = server.recv(2048)
            #while message is not "":
            print(message)
            while message:
                total_data+=message.decode("utf-8")
                message = ""
                message = server.recv(2048)
            else:
                break
        except socket.error as ex:
            #print(ex)
            break
    print(total_data, "<<<<")
    return total_data
    # ########################################## REC #############################################

def main(server, c):
    bob.generate_public_key()
    while True:
        if c:
            try:
                server.connect((IP_address, Port))
                x = {"bob": bob.public_key}
                c = False
            except socket.error as err:
                print("Connection error", err)
        try:
            server.send(json.dumps(x).encode("utf-8"))
        except socket.error as err:
            print(err)
            server.close()
            #del server
            c=True
            continue
        total = receive(server)
        server.close()
        f= json.loads(total)
        bob.generate_shared_secret(f["alice"], echo_return_key=True)
        print(bob.shared_key)
        c=False
        print("TIME")
        time.sleep(100)




if __name__ == '__main__':

    try:
        m_soc = socket_cr()
        main(m_soc,True)
    except KeyboardInterrupt:
        m_soc.close()
        print("closed")


