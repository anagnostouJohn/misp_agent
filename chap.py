import hashlib
import string
import random

from Crypto.Cipher import AES

client_chap_key = "aw27WlgqGGCUc6APv0EUlWsh1i"

def id_generator(size=6, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


#file = open("rundom_str.txt","w")
#for i in range(100000):
#    file.write(id_generator()+"\n")


key = "hello"

hex_key = hashlib.sha256(key.encode("utf-8")).digest()
IV = 16 * b'\x00'
mode = AES.MODE_CFB


challenge = id_generator()



def cr_encr(hex_key1):
    return AES.new(hex_key1, mode, IV=IV)



def encr_file(hex_key):
    file = open("rundom_str.txt", "r")
    x = file.read()
    encryptor = cr_encr(hex_key)
    zz = encryptor.encrypt(x.encode("utf-8"))
    new_file = open("encr_file.txt","wb")
    new_file.write(zz)


def decr_file(hex_key):
    file = open("encr_file.txt", "rb")
    x = file.read()
    encryptor = cr_encr(hex_key)
    zz = encryptor.decrypt(x)
    print(zz.decode("utf-8"))

def decr_file_ch(hex_key,challenge,challenge_cl):
    file = open("encr_file.txt", "rb")
    x = file.read()
    encryptor = cr_encr(hex_key)
    zz = encryptor.decrypt(x)
    final = zz.decode("utf-8")
    final = final.split()
    #print(final)
    for i in final:
        #print(type(i))
        hex_key = hashlib.sha256((i + challenge).encode("utf-8")).digest()
        if challenge_cl == hex_key:
            print("SUCSESS")





def chap_cl(client_chap_key,challenge):
    hex_key = hashlib.sha256((client_chap_key+challenge).encode("utf-8")).digest()
    return hex_key




challenge_cl = chap_cl(client_chap_key,challenge)


decr_file_ch(hex_key,client_chap_key,challenge,challenge_cl)




#encr_file(hex_key)


#decr_file(hex_key)
#encryptor = encr_file(hex_key)



#def client_chap():
#def server_chap():



