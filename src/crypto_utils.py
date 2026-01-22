##############
# IMPORT SECTION
##############
import os
from cryptography.fernet import Fernet
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify, unhexlify

##############
# FUNCTION SECTION
##############
def generate_aes_key():
    """
    Genera 16 byte di entropia pura.
    PyCryptodome Shamir accetta stringhe di byte di lunghezza 16.
    """
    return os.urandom(16)

def split_key(key, threshold, shares_count):
    """Divide la chiave in N frammenti con soglia T."""
    # key deve essere lunga esattamente 16 byte
    shares = Shamir.split(threshold, shares_count, key)
    return [(idx, hexlify(share).decode()) for idx, share in shares]

def recover_key(shares_list):
    """Ricostruisce la chiave dai frammenti."""
    formatted_shares = [(idx, unhexlify(share_hex)) for idx, share_hex in shares_list]
    return Shamir.combine(formatted_shares)

def rsa_encrypt(data_bytes, public_key_path):
    """Cifra byte usando la chiave pubblica RSA."""
    recipient_key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(data_bytes)

def rsa_decrypt(encrypted_data, private_key_path):
    """Decifra byte usando la chiave privata RSA."""
    private_key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)