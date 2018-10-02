from OpenSSL import crypto, SSL
import os
from socket import gethostname
from time import gmtime, mktime
from os.path import exists, join

#CERT_FILE = "myapp.crt"
#KEY_FILE = "myapp.key"

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"


def create_self_signed_cert(cert_dir):
    if not exists(join(cert_dir, CERT_FILE)) or not exists(join(cert_dir, KEY_FILE)):
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)
# create a self-signed cert
        cert = crypto.X509()
        print(dir(cert.get_subject()))
        cert.get_subject().C = "UK"
        cert.get_subject().ST = "United Kingdom"
        cert.get_subject().L = "Athens"
        cert.get_subject().O = "FfF"
        cert.get_subject().OU = "FfF"
        cert.get_subject().CN = gethostname()
        cert.set_serial_number(1100)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')

        open(join(cert_dir, CERT_FILE), "wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(join(cert_dir, KEY_FILE), "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

create_self_signed_cert(os.getcwd())
#create_self_signed_cert("")
