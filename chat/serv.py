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



hash_256 = hashlib.sha256()
alice = DiffieHellman()


KEYFILE = os.getcwd()+'/certs/key.pem'
CERTFILE = os.getcwd()+'/certs/cert.pem'

Port = 8210
IP_address = '192.168.168.167'

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
        #server = ssl.wrap_socket(server, keyfile=KEYFILE, certfile=CERTFILE, server_side=True,) #(ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA")
        server.listen()
        return server
    except socket.error as err :
        print ("Socket Error :", err)


class client(Process):
    def __init__(self,socet,ip_port):
        super(client, self).__init__()
       #self.alice = DiffieHellman()
        self.key = None
        self.socet = socet
        self.ip = ip_port[0]
        self.port = ip_port[1]
        self.shared = None
        self.time_con = None 


    def run(self):
        self.time_con = time.time()
        #print(time.time())
        #print(self.ip)
        #print(self.port)
        self.chap()
        #self.dh()


    def decr_file(client_chal,client_hash,db,encryp):


        x = db.lgetall("encr_pass")
        #print(x)
        for i in x:
            #print(bytes.fromhex(i))
            pp = bytes.fromhex(i)
            #print(dir(i))
            bb = encryp.decrypt(pp)
            print(bb.decode("utf-8"))
            #print(bb.decode("utf-8"))







    def chap(self):
        db = pickledb.load('/home/john/Desktop/Workspace/thesis/chat/test.db', False)
        encryptor = cr_encr(return_sha256(key))
        challenge = id_generator(10)
        server_encrypt = encryptor.decrypt(bytes.fromhex(db.get("encr_pass_serv")))
        data = {"challenge":challenge,"hash": (hmac.new(str(self.time_con)[:9].encode("utf-8"),((server_encrypt.decode("utf-8")+str(self.time_con)[:9]+challenge).encode("utf-8"))).digest()).hex()}
        send_json = json.dumps(data)
        print(send_json)
        self.socet.send(send_json.encode("utf-8"))
        data_get = self.socet.recv(1024)
        data_get= json.loads(data_get)
        print("DATA GET",data_get)
        x = db.lgetall("encr_pass")
        for i in x:
            list_clients = encryptor.decrypt(bytes.fromhex(i)).decode("ISO-8859-1")
            client_hash = {"hash": (hmac.new(str(self.time_con)[:9].encode("utf-8"),((list_clients+str(self.time_con)[:9]+data_get["challenge"]).encode("utf-8"))).digest()).hex()}
            if client_hash["hash"] == data_get["hash"]:
                print("HELLOOOOOO")
            
            
        #print(data_get)
        

    def dh(self):
        alice.generate_public_key()
        print(alice.public_key)
        total_data = ""
        print("EDO")
        while True:
            try:
                print("MESA")
                message = ""
                self.socet.settimeout(1)
                message = self.socet.recv(2048)
                while message is not "":
                    total_data+=message.decode("utf-8")
                    message = ""
                    message = self.socet.recv(2048)
                else:
                    break
            except socket.error as ex:
                print("receive Time out ",ex)
            x = {"alice":alice.public_key}
            self.socet.send(json.dumps(x).encode("utf-8"))
            f = json.loads(total_data)
            alice.generate_shared_secret(f["bob"], echo_return_key=True)
            self.shared = alice.shared_key
            print(">>>>",self.shared)
            print("END")
            #self.join()
            break




def main(server):
    clients = []
    while True :
        try:
            server.settimeout(1)
            conn, addr = server.accept()
            new_client = client(conn, addr)

            #conn, addr = server.accept()
            #clientthread(conn, addr )
            #

            #t1.start()
            clients.append(new_client)
            clients[0].start()
            clients[0].join()
            del clients[0]
            print (len(clients),"LENGTH")
            #t1 = Process(target=clientthread, args=(clients[0]))
        except socket.error as e:
            print("Waiting for Connection : ",e)


if __name__ == '__main__':

    try:
        m_soc = socket_cr()
        main(m_soc)
    except KeyboardInterrupt:
        m_soc.close()
        print("closed")