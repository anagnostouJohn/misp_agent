#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keys import misp_url, misp_key
from pymisp import PyMISP
import socket
import ssl
import os
#import sys
import yara
import re
import fileinput

KEYFILE = os.getcwd()+'/certs/key.pem'
CERTFILE = os.getcwd()+'/certs/cert.pem'

def check_yara(path):
    try:
        x = yara.compile(path)
        print("OK", x)
        x.save(os.getcwd()+"/yara_files/saved_file.yara")
        return
    except yara.SyntaxError as err:
        print(err)
        f = err.args[0]
        #n = re.search(r'\((.*?)\)',f).group(1)#Eyresh kati pou einai anamesa se ()
        z = re.findall(r'"([^"]*)"', f) #Eyresh kati pou einai anamesa se ""
        counter = 0
        with fileinput.FileInput(path, inplace=True) as file:
            for line in file:
                print(line.replace(z[0], (z[0]+str(counter))), end='')                
                counter+=1
        check_yara(path)



def init(url, key):
    return PyMISP(url, key, False, 'json', debug=False)
    
    
# ##############################################################################################################

def echo_client(s):
    while True:
        (agent,a) = s.accept()
        print (type(agent), type(a)) 
        agent.send(b'OK')
        x = input("Enter Something: ")
        print(x)
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
    

    #ssl_soc = echo_server((socket.gethostbyname('localhost'), 8089))
    misp = init(misp_url, misp_key)
    result_ip_src= misp.get_all_attributes_txt(type_attr="ip-src")
    result_ip_dest = misp.get_all_attributes_txt(type_attr="ip-dst")
    result_yara= misp.get_all_attributes_txt(type_attr="yara")
    path = os.getcwd()+"/yara_files/yara_file.yara"
    print(path)
    file_new = open(path, "w")
    
    file_new.write(result_yara.text)
    file_new.close()
    check_yara(path)
    hh = yara.load(os.getcwd()+"/yara_files/saved_file.yara")
    print(f"END {hh}")
    #print("SRC : ", result_ip_src.text, "DEST : ", result_ip_dest.text,  "YARA : ", result_yara.text)

    
    #while True:
    #    echo_client(ssl_soc)





