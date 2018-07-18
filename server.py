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
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



KEYFILE = os.getcwd()+'/certs/key.pem'
CERTFILE = os.getcwd()+'/certs/cert.pem'


def check_wrong_yara(path):
    book = open(path, "r")
    all_lines = book.read()
    f = all_lines.split("rule")
    for i in reversed(f):
        print(i)
        try:
            yara.compile(source="rule " + i)
        except Exception as err:
            #logging.error('Error in Yara File : ' + str(err) + " Yara File : " + i + "\n")
            print(err)
            f.remove(i)

    book.close()
    file = open(os.getcwd()+"/yara_files/clean.yara", "w")

    for i in f:
        print(">>>>>>>>>>>>>",i,"<<<<<<<<<<<<<<<<<<<<")
        file.write("rule " + i + " \n")
    file.close()


def check_double_yara(path):
    try:
        yara.compile(path)
        return
    except yara.SyntaxError as err:
        f = err.args[0]
        # n = re.search(r'\((.*?)\)',f).group(1)#Eyresh kati pou einai anamesa se ()
        z = re.findall(r'"([^"]*)"', f)  # Eyresh kati pou einai anamesa se ""
        counter = 0
        with fileinput.FileInput(path, inplace=True) as file:
            for line in file:
                print(line.replace(z[0], (z[0] + str(counter))), end='')
                counter += 1
    check_double_yara(path)

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
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s %(message)s', datefmt='%a, %d %b %Y %H:%M:%S', filename='program.log', level=logging.DEBUG)

    #ssl_soc = echo_server((socket.gethostbyname('localhost'), 8089))
    misp = init(misp_url, misp_key)
    result_ip_src= misp.get_all_attributes_txt(type_attr="ip-src")
    result_ip_dest = misp.get_all_attributes_txt(type_attr="ip-dst")
    result_yara= misp.get_all_attributes_txt(type_attr="yara")
    if not os.path.exists(os.getcwd()+"/yara_files"):
        os.makedirs(os.getcwd()+"/yara_files")
    path = os.getcwd()+"/yara_files/yara_file.yara"

    #print(result_yara.text)
    #path = "test.yara"
    file_new = open(path, "w")
    
    file_new.write(result_yara.text)
    file_new.close()
    check_wrong_yara(path)
    #check_double_yara(path)
    #hh = yara.load(os.getcwd()+"/yara_files/saved_file.yara")
    #print(f"END {hh}")
    #print("SRC : ", result_ip_src.text, "DEST : ", result_ip_dest.text,  "YARA : ", result_yara.text)

    
    #while True:
    #    echo_client(ssl_soc)





