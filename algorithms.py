import jsocket
import coloredlogs, logging
import binascii
import argparse
import sys
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dsa, utils, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Sugere-se que sejam implementadas funções genéricas de cifra/decifra/cálculo 
# de um MAC/verificação de um MAC de textos.  
# Estas fun ̧c ̃oes podem aceitaro texto, algoritmo e outros argumentos, 
# realizando uma a ̧c ̃ao espec ́ıfica.

# Static vars
logger = logging.getLogger('jclient')
ALGORITHMS = ['3DES', 'AES-128']

def gen_key(data, name, digest_algorithm=None):
    """
        Function to gen a symm key
        :param data: data 
        :param name: cipher algorithm 
        :param digest_algorithm: digest algorithm to use
    """

    if digest_algorithm != None:
        if digest_algorithm == 'SHA256':
            algorithm = hashes.SHA256()
        elif digest_algorithm == 'SHA512':
            algorithm = hashes.SHA512()
        else:
            logger.error('Algoritmo n encontrado')
            raise Exception('No algorithm found!')
    else:
        algorithm = hashes.SHA256() # Default

    data = data.encode()

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm = algorithm,
                     length = 32,
                     salt = salt,
                     iterations = 10000,
                     backend = default_backend(),
                     )
    gen_key = kdf.derive(data)

    if algorithm == 'AES-128':
        gen_key = gen_key[:16]
    elif algorithm == '3DES':
        gen_key = gen_key[:8]

    return gen_key

def gen_digest(data, algorithm):
    """
        function to generate digested data
        :param data: data to digest
        :param: digest algorithm
    """

    hash_alg = None
    be = default_backend()

    if algorithm == 'SHA256':
        hash_alg = hashes.SHA256()
    elif algorithm == 'SHA512':
        hash_alg = hashes.SHA512()
    else:
        raise Exception("No algoritmh found!")

    digested_data = hashes.Hash(hash_alg, be)
    digested_data.update(data)

    return digested_data.finalize()

def gen_mac(data, key, name, mode_name):
    """
        function to encrypt data using a symmetric key, an algorithm and a mode
        :param data: data to encrypt, 
        :param key: symmetric key
        :param name: cypher algorithm
        :param mode: cypher mode
    """
    cipher = None
    mode = None
    iv = None
    nonce = None
    tag = None

    if mode_name == "ECB":
        mode = modes.ECB()
    elif mode_name == "CBC":
        if name == "AES":
            iv = os.urandom(16)
        elif name == "3DES":
            iv = os.urandom(8)
        mode = modes.CBC(iv)
    elif mode_name == "GCM":
        iv = os.urandom(12)
        mode = modes.GCM(iv)
    elif mode_name == "None":
        mode = None
    else:
        raise Exception('No algorithm found!')

    if name == "AES":
        if mode == None:
            raise Exception("No mode was provided for AES")
        key = key[:16]
        block_size = algorithms.AES(key).block_size
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())

    elif name == "3DES":
        if mode == None or mode_name == "GCM":
            raise Exception("Mode provided isn't supported by 3DES")
        key = key[:8]
        block_size = algorithms.TripleDES(key).block_size
        cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())

    elif name == "ChaCha20":
        if mode != None:
            raise Exception("ChaCha20 doesn't support any modes")
        key = key[:32]
        nonce = os.urandom(16)
        block_size = len(data)

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=mode, backend=default_backend()
        )

    else:
        raise Exception("Algorithm not found!")

    encryptor = cipher.encryptor()

    padding = block_size - len(data) % block_size

    if name == "AES":
        padding = 16 if padding == 0 else padding
    elif name == "3DES":
        padding = 8 if padding == 0 else padding

    if name != "ChaCha20":
        data += bytes([padding] * padding)

    cryptogram = encryptor.update(data) + encryptor.finalize()

    if mode_name == "GCM":
        tag = encryptor.tag

    return cryptogram, iv, nonce, tag