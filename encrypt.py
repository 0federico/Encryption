#!/usr/bin/python3
import optparse
from getpass import getpass
from cryptography.fernet import Fernet
import os
def chiave_da_password(passwd):
    import base64
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    password = passwd.encode()
    salt = b'\xaes\xff\x80\xe2{(\xfcG\xbdk\xed\xb9\x15n7'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def scegli_chiave(par=0):
    if par == 0:
        ris2 = req('Use 0 to use a password o 1 to generate a key randomly')
        if ris2 == '1':
            key = Fernet.generate_key()
        elif ris2 == '0':
            key1 = chiave_da_password(req('Insert the password',passwd=1))
            key = chiave_da_password(req('Insert the password again',passwd=1))
            if key != key1:
                print('Passwords do not match!')
                exit(0)
        else:
            print('Error')
            return '-1'
    if par == 1:
        ris2 = req('Use 0 to use a password o 1 to insert a key')
        if ris2 == '1':
            key = req('Insert the key')
        elif ris2 == '0':
            key = chiave_da_password(req('Insert the password',passwd=1))
        else:
            print('Error')
            return '-1'
    print('The key is: ' + key.decode('utf-8'))
    return key

def req(testo,passwd=0):
    print(testo)
    if passwd == 0:
        #return str(raw_input('--> '))
        return str(input('--> '))
    elif passwd == 1:
        return str(getpass('Password:'))

def criptaFile(perc,key,out=-1):
    if out == -1:
        out = perc
    file = open(perc,'rb')
    da_criptare = file.read()
    file.close()

    f = Fernet(key)
    criptato = f.encrypt(da_criptare)

    f2 = open(out,'wb')
    f2.write(criptato)
    f2.close()

def criptaDirectory(perc,key):
    tutti_i_file = os.listdir(perc)
    for i in tutti_i_file:
        percorsofile = perc + '/' + i
        try:
            os.listdir(percorsofile)
            criptaDirectory(percorsofile,key)
        except:
            criptaFile(percorsofile,key)

def decriptaFile(perc,key,out=-1):
    #key = bytes(key,'UTF-8')
    if out == -1:
        out=perc
    f = Fernet(key)
    file = open(perc)
    da_decriptare = file.read()
    file.close()
    decriptato = f.decrypt(bytes(da_decriptare,'UTF-8'))
    f3 = open(out,'wb')
    f3.write(decriptato)
    f3.close()

def decriptaDirectory(perc,key):
    tutti_i_file = os.listdir(perc)
    for i in tutti_i_file:
        percorsofile = perc + '/' + i
        try:
            os.listdir(percorsofile)
            decriptaDirectory(percorsofile,key)
        except:
            decriptaFile(percorsofile,key)


def Main():
    parser = optparse.OptionParser('usage %prog ' + '-f <target file> -r <target directory> -o <output file> -k <key> -p <password> -m <0||1>',version='%prog 1.0')
    parser.add_option('-f', dest='percorsofile',type='string', help='Location of file to encrypt/decrypt')
    parser.add_option('-r', dest='percorsodir',type='string', help='Location of the directory to encrypt/decrypt')
    parser.add_option('-o', dest='percorsofiledioutput',type='string', help='Location of file to store informations. If not specified, writing on input file. Not allowed with -r option')
    parser.add_option('-k', dest='key',type='string', help='Key to use')
    parser.add_option('-p', dest='password',type='string', help='Password to use to generate the key')
    parser.add_option('-m', dest='mode',default='0',help='Use 0 to encrypt or 1 to decrypt. Default is encrypt')

    (options, args) = parser.parse_args()
    if ((options.percorsofile == None) and (options.percorsodir == None)) or ((options.percorsofile != None) and (options.percorsodir != None)):
        print('Specify one target')
    else:
        if (options.mode != '0') and (options.mode != '1'):
            print('Mode Error!')
        else:
            if (options.key == None) and (options.password == None):
                if options.mode == '0':
                    options.key = scegli_chiave()
                else:
                    options.key = scegli_chiave(par=1)
            if options.password != None:
                options.key = chiave_da_password(options.password)
            #Tutto giusto
            if options.mode == '0':
                if (options.percorsofile != None):
                    if options.percorsofiledioutput != None:
                        criptaFile(options.percorsofile,out=options.percorsofiledioutput,key=options.key)
                    else:
                        criptaFile(options.percorsofile,key=options.key)
                else:
                    criptaDirectory(options.percorsodir,key=options.key)
            else:
                if (options.percorsofile != None):
                    if options.percorsofiledioutput != None:
                        decriptaFile(options.percorsofile,out=options.percorsofiledioutput,key=options.key)
                    else:
                        decriptaFile(options.percorsofile,key=options.key)
                else:
                    decriptaDirectory(options.percorsodir,key=options.key)


if __name__ == '__main__':
    Main()
