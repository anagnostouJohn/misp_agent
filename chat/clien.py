#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  6 13:34:29 2018

@author: john
"""
import string
import random
import pickledb
import socket
import hmac
import os
import ssl
import json
from diffiehellman.diffiehellman import DiffieHellman
import hashlib
import time
from Crypto.Cipher import AES




bob = DiffieHellman()
IP_address = '192.168.1.3'
Port = 8210

key = "hello1"
IV = 16 * b'\x00'
mode = AES.MODE_CFB



        
def cr_encr(hex_key):
    return AES.new(hex_key, mode, IV=IV)

def id_generator(size, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def return_sha256(string_to_hex):
    return hashlib.sha256(string_to_hex.encode("utf-8")).digest()


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
            while message:
                total_data += message.decode("utf-8")
                message = ""
                message = server.recv(2048)
            else:
                break
        except socket.error as ex:
            #print(ex)
            break
    #print(total_data, "<<<<")
    return total_data
    # ########################################## REC #############################################

def main(server, c, time_con):
    
    
    #db = pickledb.load('/home/john/Desktop/Workspace/thesis/chat/test_client.db', False)
    db = pickledb.load(r'C:\Users\john\Desktop\workSpace\thesis\chat\test_client.db', False)
    encryp = cr_encr(return_sha256(key))
    my_challenge = id_generator(10)
    server_id = encryp.decrypt(bytes.fromhex(db.get("encr_serv")))
    client_id = encryp.decrypt(bytes.fromhex(db.get("my")))
    print(my_challenge, "  ", server_id, "   ",client_id)
    
    bob.generate_public_key()
    while True:
        if c:
            try:
                server.connect((IP_address, Port))
                server_chap = server.recv(1024)
                server_chap = json.loads(server_chap)
                server_hash = {"server_hash": (hmac.new(str(time_con)[:9].encode("utf-8"),((server_id.decode("utf-8")+str(time_con)[:9]+server_chap["challenge"]).encode("utf-8"))).digest()).hex()}
                if server_hash["server_hash"] == server_chap["hash"]:
                    time.sleep(1)
                    data = {"challenge":my_challenge,"hash": (hmac.new(str(time_con)[:9].encode("utf-8"),((client_id.decode("utf-8")+str(time_con)[:9]+my_challenge).encode("utf-8"))).digest()).hex()} 
                    data = json.dumps(data)
                    server.send(data.encode("utf-8"))
                    x = {"bob": bob.public_key}
                    server.send(json.dumps(x).encode("utf-8"))
                    c = False
                    total = receive(server)
                    #print(total)
                    server.close()
                    f= json.loads(total)
                    bob.generate_shared_secret(f["alice"], echo_return_key=True)
                    print("SHARED KEY",bob.shared_key)
                    c=False                                        
                else:
                    server.close()
            except socket.error as err:
                #break
                print("Connection error", err)
                server.close()
                c = True
                continue

        print("TIME")
        time.sleep(100)




if __name__ == '__main__':

    try:
        m_soc = socket_cr()
        main(m_soc,True,time.time())
    except KeyboardInterrupt:
        m_soc.close()
        print("closed")


