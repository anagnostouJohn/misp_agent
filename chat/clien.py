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
import sympy
import os
import ssl
import json
from diffiehellman.diffiehellman import DiffieHellman
import hashlib
import time
from Crypto.Cipher import AES




#bob = DiffieHellman()




IP_address = '192.168.168.25'
Port = 8210

key = "hello1"
IV = 16 * b'\x00'
mode = AES.MODE_CFB
server = ""


        
def cr_encr(hex_key):
    return AES.new(hex_key, mode, IV=IV)

def id_generator(size, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def return_sha256(string_to_hex):
    return hashlib.sha256(string_to_hex.encode("utf-8")).digest()


bobSecret = random.randint(1,1000)


def socket_cr():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

def main(c, time_con):
    while True:
        db = pickledb.load('/home/john/Desktop/Workspace/thesis/chat/test_client.db', False)
        #db = pickledb.load(r'C:\Users\john\Desktop\workSpace\thesis\chat\test_client.db', False)
        encryp = cr_encr(return_sha256(key))
        my_challenge = id_generator(10)
        server_id = encryp.decrypt(bytes.fromhex(db.get("encr_serv")))
        client_id = encryp.decrypt(bytes.fromhex(db.get("my")))
        del encryp


        if c:
            try:
                server = socket_cr()
                server.connect((IP_address, Port))
                server_chap = server.recv(2048)
                server_chap = json.loads(server_chap)
                print(server_chap)
                server_hash = {"server_hash": (hmac.new(str(time_con)[:9].encode("utf-8"),((server_id.decode("utf-8")+str(time_con)[:9]+server_chap["challenge"]).encode("utf-8"))).digest()).hex()}
                if server_hash["server_hash"] == server_chap["hash"]:
                    print("NAI NAI NAI NAI")
                    try:
                        time.sleep(1)
                        data = {"challenge":my_challenge,"hash": (hmac.new(str(time_con)[:9].encode("utf-8"),((client_id.decode("utf-8")+str(time_con)[:9]+my_challenge).encode("utf-8"))).digest()).hex()}
                        data = json.dumps(data)
                        server.send(data.encode("utf-8"))
                        df_keys = json.loads(server.recv(2048))
                        B = (df_keys["primitive"] ** bobSecret) % df_keys["prime"]
                        bob_sh = {"bob": B}
                        server.send(json.dumps(bob_sh).encode("utf-8"))
                        c = False
                        bobSharedSecret = (df_keys["A"] ** bobSecret) % df_keys["prime"]
                        encryptor = cr_encr(return_sha256(str(bobSharedSecret)))
                        try:
                            mess = json.loads(encryptor.decrypt(server.recv(2048)).decode("utf-8"))
                            del encryptor
                            if mess["OK"]=="OK":
                                my_mess = {"OK11": "OK11", "cl": id_generator(10)}
                                my_mess = json.dumps(my_mess)
                                encryptor = cr_encr(return_sha256(str(bobSharedSecret)))
                                final_rep = encryptor.encrypt(my_mess.encode("utf-8"))
                                server.send(final_rep)
                                print("cccccccc",mess)
                        except Exception as ex:
                            print(ex, "FIRST")
                            server.close()
                        c=False
                    except Exception as erro:
                        print(erro, "SECOND")
                        server.close()
                        c = True
                else:
                    print("OXI OXI OXI ")
                    server.close()
                    c = True
            except socket.error as err:
                #break
                print("Connection error", err)
                server.close()
                c = True
                continue

        print("TIME", c)
        time.sleep(2)




if __name__ == '__main__':

    try:

        main(True,time.time())
    except KeyboardInterrupt:
        server.close()
        print("closed")


