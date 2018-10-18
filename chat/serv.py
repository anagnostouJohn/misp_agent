#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  6 13:33:05 2018

@author: john
"""

# Python program to implement server side of chat room.
import pickledb
import socket
import hmac
import os
import json
import hashlib
import string
import random
from multiprocessing import Process
from diffiehellman.diffiehellman import DiffieHellman
from Crypto.Cipher import AES
import time
import sympy



hash_256 = hashlib.sha256()




#alice = DiffieHellman()


KEYFILE = os.getcwd()+'/certs/key.pem'
CERTFILE = os.getcwd()+'/certs/cert.pem'

Port = 8210
IP_address = '192.168.168.25'

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
        server.bind((IP_address, Port))
        server.listen()
        return server
    except socket.error as err :
        print ("Socket Error :", err)


#     while message is not "":
#         total_data+=message.decode("utf-8")
#         message = ""
#         message = self.socet.recv(2048)
#         print(">>>>>>>",message)
#     else:
#         break
# except socket.error as ex:
#   print("receive Time out ",ex)


class client(Process):
    def __init__(self,socet,ip_port):
        super(client, self).__init__()
        self.random_prime = sympy.randprime(0, 888888888888888888888)
        self.primitive_root_of_random_prime = sympy.primitive_root(self.random_prime)
        self.secret_key = random.randint(1,1000)
        self.key = None
        self.socet = socet
        self.ip = ip_port[0]
        self.port = ip_port[1]
        self.shared_sec = None
        self.time_con = None
        self.cl_encryptor = None
        self.sha_of_shared = None





    def run(self):
        self.time_con = time.time()
        return_of_chap = self.chap()
        time.sleep(1)
        if return_of_chap==True:
            self.dh()
            self.first_message()

        else:
            return

    def first_message(self):
        mess = {"OK":"OK","cl":id_generator(10)}
        mess = json.dumps(mess)
        self.cl_encryptor = cr_encr(return_sha256(str(self.shared_sec)))
        first_m = self.cl_encryptor.encrypt(mess.encode("utf-8"))
        self.socet.send(first_m)
        self.socet.settimeout(1)
        firset_repl = self.socet.recv(1024)
        del self.cl_encryptor
        self.cl_encryptor = cr_encr(return_sha256(str(self.shared_sec)))
        firset_repl = self.cl_encryptor.decrypt(firset_repl)
        firset_repl = json.loads(firset_repl)
        print(firset_repl,  "OLA KALA MEXRI EDO")

    def chap(self):
        db = pickledb.load('/home/john/Desktop/Workspace/thesis/chat/test.db', False)
        #db = pickledb.load(r'C:\Users\john\Desktop\workSpace\thesis\chat\test.db', False)
        encryptor = cr_encr(return_sha256(key))
        challenge = id_generator(10)
        server_encrypt = encryptor.decrypt(bytes.fromhex(db.get("encr_pass_serv")))
        data = {"challenge":challenge,"hash": (hmac.new(str(self.time_con)[:9].encode("utf-8"),((server_encrypt.decode("utf-8")+str(self.time_con)[:9]+challenge).encode("utf-8"))).digest()).hex()}
        send_json = json.dumps(data)
        try:
            self.socet.send(send_json.encode("utf-8"))
        except socket.error as err :
            self.socet.close()
            return False
        self.socet.settimeout(2)
        data_get = self.socet.recv(1024)

        print(data_get, "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
        data_get= json.loads(data_get)
        x = db.lgetall("encr_pass")
        for i in x:
            list_clients = encryptor.decrypt(bytes.fromhex(i)).decode("ISO-8859-1")
            client_hash = {"hash": (hmac.new(str(self.time_con)[:9].encode("utf-8"),((list_clients+str(self.time_con)[:9]+data_get["challenge"]).encode("utf-8"))).digest()).hex()}
            if client_hash["hash"] == data_get["hash"]:
                return True
            else:
                continue
        return False



    def dh(self):
        print("EDO")
        while True:
            try:
                print("MESA")
                message = ""
                self.socet.settimeout(1)
                A = (self.primitive_root_of_random_prime ** self.secret_key) % self.random_prime
                x = {"prime": self.random_prime, "primitive": self.primitive_root_of_random_prime,"A":A}
                self.socet.send(json.dumps(x).encode("utf-8"))
                message = self.socet.recv(2048)
                f = json.loads(message)
                self.shared_sec = (f["bob"] ** self.secret_key) % self.random_prime


                return
            except Exception as erro:
                print(erro)
            time.sleep(1)




def main(server):
    clients = []
    while True :
        try:
            server.settimeout(3)
            conn, addr = server.accept()
            new_client = client(conn, addr)
            clients.append(new_client)
            new_client.start()
            new_client.join()
            #del clients[0]
            print (len(clients),"LENGTH")
        except socket.error as e:
            print("Waiting for Connection : ",e)


if __name__ == '__main__':

    try:
        m_soc = socket_cr()
        main(m_soc)
    except KeyboardInterrupt:
        m_soc.close()
        print("closed")