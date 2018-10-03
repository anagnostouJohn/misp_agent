#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  6 13:33:05 2018

@author: john
"""

# Python program to implement server side of chat room.
import socket
import os
import json
import hashlib
import string
import random
from multiprocessing import Process
from diffiehellman.diffiehellman import DiffieHellman
from Crypto.Cipher import AES



hash_256 = hashlib.sha256()
alice = DiffieHellman()


KEYFILE = os.getcwd()+'/certs/key.pem'
CERTFILE = os.getcwd()+'/certs/cert.pem'

Port = 8210
IP_address = '192.168.1.3'

key = "hello"
#hex_key = hashlib.sha256(key.encode("utf-8")).digest()
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
       #self.alice.generate_public_key()


    def run(self):
        self.chap()
        #self.dh()


    def chap(self):
        file = open("encr_fileserv.txt", "rb")
        x = file.read()

        encryptor = cr_encr(return_sha256(key))
        zz = encryptor.decrypt(x)

        zz = zz.decode("utf-8")
        final = zz.split()
        print(final[0])
        challenge = id_generator(10)
        data = {"challenge":challenge,"hash":return_sha256(final[0]+challenge).hex()}
        print(data)
        id_generator(10)
        send_json = json.dumps(data)
        print(type(send_json))
        #print(send_json.encode("utf-8"))
        #self.socet.send(send_json)


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
                #while message is not "":

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