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

# GLOBAL
backend = default_backend()

user_list = {'username_a':
             {
                 'fullname': 'User Name A',
                 'certificate': '',
                 'can_connect': True,
                 'can_read': False
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

    def _process_message(self, message: dict) -> None:
        """
        Called when a frame (JSON Object) is extracted

        :param message: The JSON object to process
        :return:
        """
        try:
            logger.debug("Process Message. Object: {}".format(message))
            self.process_client_message(eval(str(message)))
        except:
            logger.exception("process_message")

    def process_client_message(self, message: dict) -> None:
        """
        Process a message send by the client
        :param message: The JSON object to process
        :return: 
        """

        mtype = message.get('type', "").upper()

        ret = False

        if mtype == 'SECURE':
            #TODO pass for now
            # message = self.process_secure(message)
            pass
        if message is not None:
            mtype = message.get('type', "").upper()
            if mtype == 'CONNECT':
                ret = self.process_connect(message)
            elif mtype == 'AGREEMENT':
                ret = self.process_agreement(message)
            elif mtype == 'KEYEX':
                ret = self.process_keyex(message)
            elif mtype == 'AUTHN':
                ret = self.process_authn(message)
            elif mtype == 'AUTHZ':
                ret = self.process_authz(message)
            elif mtype == 'GET':
                ret = self.process_get(message)
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

        # Do Stuff

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
        logger.info(
            f'Algorithm: {self.algorithm}, Mode: {self.mode}, Hash function: {self.hash_function}, IV:{self.iv}')
        message = {'type': 'AGREEMENT_OK'}
        self._send(message)
        # Advance state
        logger.info("ADVANCING STATE")
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
        self.key = HKDF(algorithm=hashes.SHA256(), length=16, salt=os.urandom(16),
                        info=b'key_derivation',
                        backend=default_backend()
                        ).derive(shared_key)

        server_pub_key_bytes = self.public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        msg = {"type": 'SERVER_PUBLIC_KEY',
               'server_public_key': base64.b64encode(server_pub_key_bytes).decode('utf-8')}

        self.send(msg)
        # In the last message of this process advance the state
        logger.info("ADVANCING STATE")
        self.state = STATE_AUTHN
        return True

    def process_authn(self, message: dict) -> bool:
        """
        Process messages related with the Authentication process

        :param message: The JSON object from the client
        :return bool
        """

        if self.state != STATE_AUTHN:
            logger.warning("Invalid state. Discarding")
            return False

        logger.info("STATE: AUTHENTICATE")

        # do authenticate
        self.server_nonce = base64.b64decode(message["nonce"])
        # TODO: check pass.... ok
        # Load server pri_key
        with open("./sv-keys/key.pem") as k:
            self.sv_key = serialization.load_pem_private_key(k.read(), password=None, backend=default_backend())

        # Get pub_key
        hs = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hs.update(self.server_nonce)
        digested_hash = hs.finalize()

        nonce = self.sv_key.sign(digested_hash,
        padder.PSS(mgf=padder.MGF1(hashes.SHA256()), salt_length=padder.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))

        # sv certificate
        with open("./sv-keys/rootCA.crt") as s:
            self.sv_crt = x509.load_pem_x509_certificate(s.read(), backend=default_backend())
        b_sv_cert = self.sv_crt.public_bytes(serialization.Encoding.DER)

        # Send all to client
        text = str.encode(json.dumps( { "type": "AUTHN_OK", "nonce": base64.b64encode(nonce).decode("utf-8") }))
        payload, mac = self.encrypt(text)
        msg = {"type": "SECURE", "payload": base64.b64encode(payload).decode("utf-8"), "mac": base64.b64encode(mac).decode("utf-8")}

        self.send(msg)
        
        # In the last message of this process advance the state
        logger.info("ADVANCING STATE")
        self.state = STATE_AUTHZ
        return True

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

        # do authorization

        self.send({'type': 'OK'})
        # In the last message of this process advance the state
        self.state = STATE_GET
        return True

    def process_get(self, message: str) -> bool:
        """
        Process messages related with the Data Transfer process

        :param message: The JSON object from the client
        :return bool
        """

        # TODO: Função para enviar o arquivo para o cliente
        if self.state != STATE_GET:
            logger.warning("Invalid state. Discarding")
            return False

        logger.info("STATE: DATA TRANSFER")

        if not 'file_name' in message:
            logger.warning("No filename in Open")
            return False

        file_name = message.get('file_name')
        file_path = os.path.join(storage_dir, file_name)
        logger.info("Filename: {}".format(file_path))

        try:
            file = open(file_path, "rb")
            logger.info("File open")
        except Exception:
            logger.exception("Unable to open file")
            return False

        self.send({'type': 'OK'})

        payload = binascii.b2a_base64(file.read()).decode('ascii').strip()
        print(payload)

        data = {
            'type': 'DATA',
            'file_name': file_name,
            'payload': payload
        }

        self.send(data)
        file.close()

        return True

    def send(self, message: dict) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(json.dumps(message, indent=4)))
        msg = (json.dumps(message) + '\r\n').encode()
        self._send(msg)

    #TODO: codigo duplicado. ohh no!
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
        # TODO: check this
        payload = text, h_mac
        message = {'type': 'SECURE', 'payload': payload}

        return message


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
    jserver.timeout = 2
    jserver.start()


if __name__ == '__main__':
    main()
