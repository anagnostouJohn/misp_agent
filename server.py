#!/usr/bin/env python
# -*- coding: utf-8 -*-
from keys import misp_url, misp_key
from pymisp import PyMISP
import socket
import ssl
import os

KEYFILE = os.getcwd()+'/certs/key.pem'
CERTFILE = os.getcwd()+'/certs/cert.pem'

def init(url, key):
    return PyMISP(url, key, False, 'json', debug=False)
    
    
# ##############################################################################################################

def echo_client(s):
    while True:
        (agent,a) = s.accept()
        print (type(agent), type(a)) 
        agent.send(b'OK')
        x = input("Enter Something: ")
        agent.close()
        
        
        #data = s.recv(8192)
        #s.send(b'OK.')
        #print(data)
        #if data == b'':
        #    print("END")
        #    break
        #s.send(b'This is a response.')
        #print('Connection closed')
    #s.send(b'This is a response.')
    #s.close()
# ###############################################################################################################

def echo_server(address):
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(address)
    s.listen()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s_ssl = ssl.wrap_socket(s, keyfile=KEYFILE, certfile=CERTFILE, server_side=True)
    return s_ssl
    #while True:
    #	try:
    #		(c,a) = s_ssl.accept()
    #		print('Got connection', c, a)
    #		echo_client(c)
    #	except socket.error as e:
    #		print('Error: {0}'.format(e))



# ###############################################################################################################



if __name__ == '__main__':
    

    ssl_soc = echo_server((socket.gethostbyname('localhost'), 8089))
    misp = init(misp_url, misp_key)
    result_ip_src= misp.get_all_attributes_txt(type_attr="ip-src")
    result_ip_dest = misp.get_all_attributes_txt(type_attr="ip-dst")
    result_yara= misp.get_all_attributes_txt(type_attr="yara")
    print("SRC : ", result_ip_src.text, "DEST : ", result_ip_dest.text,  "YARA : ", result_yara.text)
    print("OK")
    
    while True:
        echo_client(ssl_soc)
