#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  6 13:34:29 2018

@author: john
"""

# Python program to implement client side of chat room.
import socket
import select
import sys
import json
import time

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#if len(sys.argv) != 3:
#	print "Correct usage: script, IP address, port number"
#	exit()
#IP_address = str(sys.argv[1])
#Port = int(sys.argv[2])

IP_address = '192.168.168.184'
Port = 8179
server.connect((IP_address, Port))

#while True:
x = {"data":"gh75dVNy08QGAxTP4RfSJ7Ccwq0XA4gsjmWdarTt2esa1AwDqseHLdyMzXkmIJUor4WgabO2dLCdijYpJEDGzgZXoUPi7bRSg20Jd2r9psUUcvvdWtTG7BbAGl0pQY1SxGnu9lhPApUa0IlL17lpM6wyUBipGjdjttt111HTlbKgSxxvwGydknXy6CojCUtodbjlGzAsWL7hmXRNdjSW6UuoiJ3gpaJpEteIBPwLB0rE5LAXGrGdVAJcEF6U8v6xy9TzDImABYbm27NmgNSDgk8w19lXtn4EkdVIXmdQCQtkgiqW0YnECbquqvXmvwXHt90u1AdTgK8NTi5pCPxSGbLGzsMm3sc3JquVLOlmcMn4iNNIDnoa9vTXucIZFCJE2ZB10wQrAeLaBPpi0fz9U6hr7uZCQnOUlTk3U2TL257ROkZ6uqNy44ePY83TPzRNAcnFYYsLwQ0AqGT895KCfJNtdjZl7aS0NX83UDrI62f55v7e0og1"}

server.send(json.dumps(x).encode("utf-8"))
time.sleep(1)

#
#while True:
#
#	# maintains a list of possible input streams
#	sockets_list = [sys.stdin, server]
#
#	""" There are two possible input situations. Either the
#	user wants to give manual input to send to other people,
#	or the server is sending a message to be printed on the
#	screen. Select returns from sockets_list, the stream that
#	is reader for input. So for example, if the server wants
#	to send a message, then the if condition will hold true
#	below.If the user wants to send a message, the else
#	condition will evaluate as true"""
#	read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])
#
#	for socks in read_sockets:
#		if socks == server:
#			message = socks.recv(2048)
#			print (message)
#		else:
#			message = sys.stdin.readline()
#			server.send(message.encode("utf-8"))
#			sys.stdout.write("<You>")
#			sys.stdout.write(message)
#			sys.stdout.flush()
#server.close()
