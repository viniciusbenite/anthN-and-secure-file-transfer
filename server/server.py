import json
import binascii
import argparse
import coloredlogs
import logging
import jsocket
import copy
import base64
import os
import random
import string
import re
import errno, time, socket
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as padder
from cryptography.hazmat.primitives import hashes
from cryptography import x509

logger = logging.getLogger('jserver')

# Static vars
STATE_CONNECT = 0  # Cliend Just Connected
STATE_KEYEX = 1  # Key Exchange
STATE_AUTHN = 3  # AUTHeNtication
STATE_AUTHZ = 3  # AUTHoriZation
STATE_GET = 4  # Data Transfer
STATE_AGREEMENT = 5 # Negotiation phase
STATE_CHALANGE = 6 # Chalange phase

# GLOBAL
backend = default_backend()

user_list = {'vinicius':
             {
                 'fullname': 'vinicius ribeiro',
                 'certificate': '',
                 "password": "vinicius",
                 'can_connect': True,
                 'can_read': False
             },
             'joao': {
                 'fullname': 'joao barraca',
                 'certificate': '',
                 "password": "joao",
                 'can_connect': True,
                 'can_read': True
             }
             }

storage_dir = 'files'


class ServerFactoryThread(jsocket.ServerFactoryThread):
    def __init__(self):
        super(ServerFactoryThread, self).__init__()
        """
		Default constructor
		"""
        self.state = STATE_CONNECT

        self.algorithm = None
        self.mode = None
        self.hash_function = None
        self.iv = None
        self.protocols = {
            'algorithms': ['3DES', 'AES'],
            'modes': ['ECB', 'CBC'],
            'hash_functions': ['MD5', 'SHA-256']
        }

        self.key = None
        self.private_key = None
        self.public_key = None

        self.sv_crt_pub_key = None
        self.sv_crt_pri_key = None

        self.rsa_client_pub_key = None
        self.rsa_server_pub_key = None
        self.rsa_server_pri_hey = None

    def _process_message(self, message: dict) -> None:
        """
        Called when a frame (JSON Object) is extracted

        :param message: The JSON object to process
        :return:
        """
        try:
            logger.debug("Process Message. Object: {}".format(message))
            self.process_client_message(eval(str(message)))
        except Exception as e:
            logger.exception("process_message error: {}".format(e))

    def process_client_message(self, message: dict) -> None:
        """
        Process a message send by the client
        :param message: The JSON object to process
        :return: 
        """

        mtype = message.get('type', "").upper()

        ret = False

        if message is not None:
            mtype = message.get('type', "").upper()
            if mtype == 'CONNECT':
                ret = self.process_connect(message)
            elif mtype == 'AGREEMENT':
                ret = self.process_agreement(message)
            elif mtype == 'KEYEX':
                ret = self.process_keyex(message)
            
            if mtype == 'SECURE':
                # if msg is secure, decrpyt it
                payload = base64.b64decode(message['payload']) # Bytes
                h_mac = base64.b64decode(message['h_mac'])
                data = self.decrypt(payload, h_mac, message)
                dec_msg = json.loads(data)
                mtype = dec_msg.get('type', '')
                if mtype == 'AUTHN_REQ':
                    ret = self.process_authn(dec_msg)
                elif mtype == "PWD_CHALANGE_REQ":
                    self.send_chalange_pass(dec_msg)
                    ret = True
                elif mtype == "CHALANGE_PWD_REP":
                    self.process_chalange_pass(dec_msg)
                    ret = True
                elif mtype == "AUTHZ_REQ":
                    ret = self.process_authz(dec_msg)
                elif mtype == 'FILE_REQ':
                    ret = self.process_get(dec_msg)
                else:
                    logger.warning(
                        "Invalid message type: {}".format(message['type']))

        if not ret:
            try:
                self.send(
                    {'type': 'ERROR', 'message': 'See server and restart the process'})
            except:
                pass  # Silently ignore

            logger.info("Closing connection")

            self.state = STATE_CONNECT
            self.close()

    def process_connect(self, message: dict) -> bool:
        """
        Process a connect request from the client
        Nothing much is done. Maybe we can authorize the IP?
        """

        if self.state != STATE_CONNECT:
            logger.warning("Invalid state. Discarding")
            return False
        logger.info("STATE: CONNECT")

        # Do Stuff ???????

        self.send({'type': 'CONNECT_OK'})
        logger.info("ADVANCING STATE")
        self.state = STATE_AGREEMENT
        # self.state = STATE_KEYEX # original
        return True

    def process_agreement(self, message: str) -> bool:
        self.state = STATE_AGREEMENT

        # Definir alg
        if message['algorithm'] not in self.protocols['algorithms']:
            logger.info('Algorithm not found!')
            return False
        self.algorithm = message["algorithm"]

        # Definir modo
        if message['mode'] not in self.protocols['modes']:
            logger.info('Mode not found!')
            return False
        self.mode = message["mode"]

        # Definir sinstese
        if message['hash_functions'] not in self.protocols['hash_functions']:
            logger.info('hash_function not found!')
            return False
        self.hash_function = message["hash_functions"]

        # Definir iv
        self.iv = base64.b64decode(message['iv'])

        logger.info("NEGOTIATION ONGOING. RECEIVED FROM CLIENT:")
        logger.info( "Algorithm -> {}, mode -> {}, hash function -> {} and iv -> {}".format(self.algorithm, self.mode, self.hash_function, self.iv))
        message = {'type': 'AGREEMENT_OK'}
        self.send(message)
        # Advance state
        logger.info("ADVANCING TO STATE_KEYEX")
        self.state = STATE_KEYEX
        return True

    def process_keyex(self, message: dict) -> bool:
        """
        Process messages related with the Key Exchange process

        :param message: The JSON object from the client
        :return bool
        """
        if self.state != STATE_KEYEX:
            logger.warning("Invalid state. Discarding")
            return False
        logger.info("STATE: KEY_EXCHANGE")

        # do key exchange

        # Primes
        p = message['p']
        g = message['g']
        params_number = dh.DHParameterNumbers(p, g)
        params = params_number.parameters(default_backend())

        # Private key
        self.private_key = params.generate_private_key()
        # Public key
        self.public_key = self.private_key.public_key()

        client_pub_key_bytes = base64.b64decode(message['public_key'])
        client_pub_key = serialization.load_der_public_key(
            client_pub_key_bytes, backend=default_backend())

        shared_key = self.private_key.exchange(client_pub_key)

        # Derivation
        self.key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'derivation', backend=default_backend()).derive(shared_key)

        server_pub_key_bytes = self.public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        msg = {"type": 'SERVER_PUBLIC_KEY', 'server_public_key': base64.b64encode(server_pub_key_bytes).decode('utf-8')}

        self.send(msg)
        # In the last message of this process advance the state
        logger.info("ADVANCING TO STATE_AUTHN")
        self.state = STATE_AUTHN
        return True

    def process_authn(self, message: dict) -> bool:
        """
        Process messages related with the Authentication process

        :param message: The JSON object from the client
        :return bool
        """

        if self.state != STATE_AUTHN:
            logger.warning("Invalid state (AUTHN). Discarding")
            return False

        logger.info("STATE: AUTHENTICATE")

        # do authenticate
        logger.debug("Got: {}".format(message))
        self.server_nonce = base64.b64decode(message['nonce'])

        # Load server pri_key
        with open("/home/vinicius/Desktop/sio-1920-proj_época_especial/server/sv-keys/sv-key.pem", "rb") as f: 
            data = f.read()
            self.sv_crt_pri_key = serialization.load_pem_private_key(data, password=None, backend=default_backend())

        # Get pub_key
        self.sv_crt_pub_key = self.sv_crt_pri_key.public_key()
    
        hs = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hs.update(self.server_nonce)
        digested_hash = hs.finalize()

        nonce = self.sv_crt_pri_key.sign(digested_hash, padder.PSS(mgf=padder.MGF1(hashes.SHA256()), salt_length=padder.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))

        # sv certificate
        with open("/home/vinicius/Desktop/sio-1920-proj_época_especial/server/sv-keys/server.crt", "rb") as f: 
            data = f.read()
            self.sv_crt = x509.load_pem_x509_certificate(data, backend=default_backend())
        b_sv_cert = self.sv_crt.public_bytes(serialization.Encoding.DER)

        # Send all to client
        text = str.encode(json.dumps( { "type": "KEY_GEN_OK", "nonce": base64.b64encode(nonce).decode("utf-8"), "sv_cert": base64.b64encode(b_sv_cert).decode('utf-8') }))
        # Encrypted message
        payload, mac = self.encrypt(text)
        msg = {"type": "SECURE", "payload": base64.b64encode(payload).decode("utf-8"), "h_mac": base64.b64encode(mac).decode("utf-8")}

        self.send(msg)
        logger.info("CERETIFICATE SENDED")

        # Chalange request #

        # In the last message of this process advance the state
        logger.info("ADVANCING STATE")
        self.state = STATE_CHALANGE
        return True

    def send_chalange_pass(self, message: str) -> None:
        """
            Send a password chalange to the client
            :param message: chalange request from client
        """
        if self.state != STATE_CHALANGE:
            logger.warning("Invalid state (CHALANGE). Discarding")
            raise Exception("Something went wront while sending chalange pass")
        logger.info("SENDING CHALANGE PASSWORD")
        b_rsa_client_pub_key = base64.b64decode(message['RSA_PUB_KEY'])
        self.rsa_client_pub_key = serialization.load_der_public_key(b_rsa_client_pub_key, backend=default_backend())
        self.chalenge_nonce = os.urandom(16)
        text = str.encode(json.dumps({ "type": 'CHALANGE_PASS', "nonce": base64.b64encode(self.chalenge_nonce).decode("utf-8") }))
        payload, mac = self.encrypt(text)
        msg = { "type": "SECURE", "payload": base64.b64encode(payload).decode("utf-8"), "h_mac": base64.b64encode(mac).decode("utf-8") }
        self.send(msg)

    def process_chalange_pass(self, message: str) -> None:
        """
            Verify if the chalange reply is corrent
            :param message: chalange reply from client
        """
        if self.state != STATE_CHALANGE:
            logger.warning("Invalid state (CHALANGE). Discarding")
            raise Exception("WRONG STATE!!")
        logger.info("PROCESSING CHALANGE PASSWORD")
        self.user = message["user"]
        self.pwd = base64.b64decode(message["password"])
        if self.user not in user_list.keys():
            self.send( { "type": "ERROR", "payload": "Wrong username/password" } )
            raise Exception("Something went wrong. Check your user/pass")
        else:
            password = user_list.get(self.user).get("password").encode() + self.chalenge_nonce
            hs = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hs.update(password)
            digest = hs.finalize()
            try:
                self.rsa_client_pub_key.verify(self.pwd, digest, padder.PSS(mgf=padder.MGF1(hashes.SHA256()), salt_length=padder.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))
                self.send({ "type": "AUTHN_OK" })
                logger.info("User {} authenticated".format(self.user))
                self.state = STATE_AUTHN
            except Exception as e:
                logger.info("Something went wrong... {}".format(e))
                self.send({ "type": "ERROR", "payload": "Invalid signature" })

    def process_authz(self, message: dict) -> bool:
        """
        Process messages related with the Authorization process

        :param message: The JSON object from the client
        :return bool
        """

        if self.state != STATE_AUTHZ:
            logger.warning("Invalid state. Discarding")
            return False

        logger.info("STATE: AUTHORIZE")
        user = message['user']

        # do authorization
        if user_list.get(user).get("can_read") is False:
            self.send({ "type": "ERROR", "payload": "User can't download files" })
            raise Exception("User can not download files from server")

        logger.info("USER IS AUTHORIZED TO DOWNLOAD FILES")
        self.send({'type': 'GET_OK', "payload": "AUTHZ_OK"})
        
        # In the last message of this process advance the state
        logger.debug("ADVANCING TO GET STATE")
        self.state = STATE_GET
        return True

    def process_get(self, message: str) -> bool:
        """
        Process messages related with the Data Transfer process

        :param message: The JSON object from the client
        :return bool
        """
        if self.state != STATE_GET:
            logger.warning("Invalid state. Discarding")
            return False

        logger.info("STATE: DATA TRANSFER")
        if not 'file_name' in message:
            logger.warning("No filename in Open")
            return False

        file_name = message.get('file_name')
        logger.info("FILE NAME -> {}".format(file_name))
        file_path = os.path.join(storage_dir, file_name)
        logger.info("Filename: {}".format(file_path))

        try:
            file = open(file_path, "rb")
            logger.info("File open")
        except Exception:
            logger.exception("Unable to open file")
            return False

        self.send( {'type': 'DOWNLOAD_OK'} )

        payload = binascii.b2a_base64(file.read()).decode('ascii').strip()
        logger.info("Payload: {}".format(payload))

        data = str.encode(json.dumps({
            'type': 'DATA',
            'file_name': file_name,
            'payload': payload
        }))
        payload, mac = self.encrypt(data)
        msg = { "type": "SECURE", "payload": base64.b64encode(payload).decode("utf-8"), "h_mac": base64.b64encode(mac).decode("utf-8") }
        self.send(msg)
        file.close()

        return True

    # Auxiliar functions. Jogar pra outro arquivo
    def send(self, message: dict) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(json.dumps(message, indent=4)))
        try:
            self.send_obj(json.dumps(message, indent=4))
        except Exception as e:
            logger.exception("Excpetion -> {}".format(e))

    #TODO: codigo duplicado. ohh no, too bad!
    def encrypt(self, message: dict) -> dict:
        """
            Encrypt a message
            
            :param message: Message to encrypt
        """
        cipher = None
        block_size = 0

        # Encrypt
        # Algorithm
        if self.algorithm == 'AES':
            alg = algorithms.AES(self.key)
            block_size = alg.block_size
        elif self.algorithm == '3DES':
            alg = algorithms.TripleDES(self.key)
            block_size = alg.block_size

        # Mode
        if self.mode == 'ECB':
            modo = modes.ECB()
        elif self.mode == 'CBC':
            modo = modes.CBC(self.iv)
        cipher = Cipher(alg, modo, backend=default_backend())

        # Synthesis
        if self.hash_function == 'SHA-256':
            sintese = hashes.SHA256()
        elif self.hash_function == 'MD5':
            sintese = hashes.MD5()
        encryptor = cipher.encryptor()

        # Convert to base64
        msg = base64.b64encode(message)
        padder = padding.PKCS7(block_size).padder()
        p_data = padder.update(msg) + padder.finalize()
        text = encryptor.update(p_data) + encryptor.finalize()
        h = hmac.HMAC(self.key, sintese, backend=default_backend())
        h.update(text)
        h_mac = h.finalize()

        return text, h_mac

    def decrypt(self, text, mac, message: dict) -> dict:
        """
            Decrypts a message
        
            :param message: Message to encrypt
        """
        mtype = message.get('type', '')

        if mtype != "SECURE":
            logger.error("Cannot decrypt message")
            raise Exception("Cannot decrypt message")

        cipher = None
        block_size = 0
        # payload = message.get('payload')
        logger.debug("Got payload: {}".format(text))

        # TODO: duplicação de código. CHECK THIS
        # Algorithm
        if self.algorithm == 'AES':
            alg = algorithms.AES(self.key)
            block_size = alg.block_size
        elif self.algorithm == '3DES':
            alg = algorithms.TripleDES(self.key)
            block_size = alg.block_size

        # Mode
        if self.mode == 'ECB':
            modo = modes.ECB()
        elif self.mode == 'CBC':
            modo = modes.CBC(self.iv)
        cipher = Cipher(alg, modo, backend=default_backend())

        # Synthesis
        if self.hash_function == 'SHA-256':
            sintese = hashes.SHA256()
        elif self.hash_function == 'MD5':
            sintese = hashes.MD5()

        # Decrypt msg
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(block_size).unpadder()
        h = hmac.HMAC(self.key, sintese, backend=default_backend())
        h.update(text)
        h.verify(mac)
        p_data = decryptor.update(text) + decryptor.finalize()
        data = unpadder.update(p_data) + unpadder.finalize()
        final_data = base64.b64decode(data)

        return final_data

    
def main():
    global storage_dir

    parser = argparse.ArgumentParser(description='Sends files to clients.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages (default=False)',
                        default=0)
    parser.add_argument('-p', type=int, action='store',
                        dest='port', default=5000,
                        help='TCP Port to use (default=5000)')

    parser.add_argument('-d', type=str, action='store', required=False, dest='storage_dir',
                        default='files',
                        help='Where get the files (default=./files)')

    args = parser.parse_args()
    storage_dir = os.path.abspath(args.storage_dir)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port

    if port <= 0 or port > 65535:
        logger.error("Invalid port")
        return

    if port < 1024 and not os.geteuid() == 0:
        logger.error("Ports below 1024 require eUID=0 (root)")
        return

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info(
        "Starting.\n- Port: {}\n- LogLevel: {}\n- Storage: {}".format(port, level, storage_dir))

    jserver = jsocket.ServerFactory(
        ServerFactoryThread, address='0.0.0.0', port=port)
    jserver.timeout = 99999
    jserver.start()


if __name__ == '__main__':
    main()
