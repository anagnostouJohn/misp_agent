#!/usr/bin/env python
# -*- coding: utf-8 -*-
from diffiehellman.diffiehellman import DiffieHellman
from keys import misp_url, misp_key
from pymisp import PyMISP
import socket
import sys
import ssl
import os
#import sys
import time
import yara
import re
import fileinput
import threading 
from multiprocessing import Process



KEYFILE = os.getcwd()+'/certs/key.pem'
CERTFILE = os.getcwd()+'/certs/cert.pem'

def init(url, key):
    return PyMISP(url, key, False, 'json', debug=False)

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

# ##############################################################################################################
    
class client:
    def __init__(self,socet,ip_port,s):
        self.alice = DiffieHellman()
        self.key = None
        self.socet = socet
        self.ip = ip_port[0]
        self.port = ip_port[1]
        self.alice.generate_public_key() 
        #self.ip = ip
    def df(self):
        m_df = {["alice":self.alice.public_key]}        
        self.socet.send(json.dumps(m_df))
        data = self.socet.recv(json.dumps(m_df))
        if data: 
            
        
        
        

    
# ##############################################################################################################

def echo_client(s):
    s.settimeout(1)
    clients = []
    threats = []
    while True:
        try: 
            clients.append(s.accept())
            threats.append(threading.Thread(target = clientthread, args = (clients[-1])))
            
            
            
            #(cl_socet,ip_port,s)            
            #server_df = 
            #print (type(agent), type(a)) 
            #print(agent,"__",a)
            #agent.send(b'OK1111')
            #x = input("Enter Something: ")
            #print(x)
            #agent.close()
        except socket.timeout:
            print("Waiting")
        
        
        
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
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(address)
        s.setblocking(1)
        
        #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_ssl = ssl.wrap_socket(s, keyfile=KEYFILE, certfile=CERTFILE, server_side=True)
        s_ssl.listen()
        
        return s_ssl
    except Exception as err:
        print(f"Error while creating Socket {err}")
        
    #while True:
    #	try:
    #		(c,a) = s_ssl.accept()
    #		print('Got connection', c, a)
    #		echo_client(c)
    #	except socket.error as e:
    #		print('Error: {0}'.format(e))



# ###############################################################################################################


def main(ssl_soc):
    

#    misp = init(misp_url, misp_key)
#    result_ip_src= misp.get_all_attributes_txt(type_attr="ip-src")
#    result_ip_dest = misp.get_all_attributes_txt(type_attr="ip-dst")
#    result_yara= misp.get_all_attributes_txt(type_attr="yara")
#    path = os.getcwd()+"/yara_files/yara_file.yara"
#    print(path)
#    file_new = open(path, "w")
#    
#    file_new.write(result_yara.text)
#    file_new.close()
#    check_yara(path)
#    hh = yara.load(os.getcwd()+"/yara_files/saved_file.yara")
#    print(f"END {hh}")
#    #print("SRC : ", result_ip_src.text, "DEST : ", result_ip_dest.text,  "YARA : ", result_yara.text)

    
    while True:
        print("KO")
        #print (ssl_soc.getdefaulttimeout())
        echo_client(ssl_soc)
        time.sleep(1)
        
        
    



if __name__ == '__main__':

    try:
        ssl_soc = echo_server((socket.gethostbyname('192.168.168.184'), 8190))
        print("OK")
        print(ssl_soc)
        main(ssl_soc)
        

    except KeyboardInterrupt:
        ssl_soc.close()
        print("closed")
            
            
    
    
    
    
    
    
    
    
    
#            print(ssl_soc)
#        except socket.Exception as ex:
#            print(ex)
#            sys.exit()
#            
#        #main(ssl_soc)
#    except KeyboardInterrupt:
#        print("EDOOOO")
#        ssl_soc.shutdown(1)
#        
    







