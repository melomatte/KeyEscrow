'''
Questo script contiene le funzioni necessarie per la gestione delle chiavi nel prototipo.
Le funzioni che sono contenute nel file sono:
    - generate_aes_key() = genera una chiave simmetrica di 128 bit
    - split_key(key, threshold, n) = divide la chiave key secondo Shamir in N frammenti, con soglia di ricostruzione pari a threshold
    - recover_key(shares_list) = ricostruisce la chiave utilizzando i frammenti recuperati
    - rsa_encrypt(data_bytes, public_key_path) =  cifratura dati attraverso chiave pubblica con padding OAEP (per rompere determinismo RSA)
    - rsa_decrypt(encrypted_data, private_key_path) = decifratura dati attraverso chiave privata
'''

##############
# IMPORT SECTION
##############

import os
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify, unhexlify

##############
# FUNCTION SECTION
##############

def generate_aes_key():
    return os.urandom(16)

def split_key(key, threshold, n):
    shares = Shamir.split(threshold, n, key)
    return [(idx, hexlify(share).decode()) for idx, share in shares]

def recover_key(shares_list):
    formatted_shares = [(idx, unhexlify(share_hex)) for idx, share_hex in shares_list]
    return Shamir.combine(formatted_shares)

def rsa_encrypt(data_bytes, public_key_path):
    recipient_key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(data_bytes)

def rsa_decrypt(encrypted_data, private_key_path):
    private_key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)