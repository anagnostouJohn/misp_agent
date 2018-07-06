import socket, ssl
import os

port = 8089
ip = "127.0.0.1"
CERT = os.getcwd()+'/certs/cert.pem'

while True:



    # Require a certificate from the server. We used a self-signed certificate
    # so here ca_certs must be the server certificate itself.
    #f.read()
    #ssl_sock.sendfile(f,0)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("EDO")
    ssl_sock = ssl.wrap_socket(s,cert_reqs=ssl.CERT_REQUIRED, ca_certs = CERT)
    print ("ED2O")
    ssl_sock.connect((ip, port))
    print ("EDO3")
    print(ssl_sock.recv(8087).decode("utf-8"))
    print ("EDO4")
    ssl_sock.write(str(input("Enter Something: ")).encode())
    ssl_sock.close()
