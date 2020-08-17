import jsocket
import coloredlogs, logging
import binascii
import argparse

import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as pdr
from cryptography import x509

logger = logging.getLogger('jclient') 

# Static vars
STATE_INITIAL = 0
STATE_KEYEX = 1
STATE_OPEN = 2
STATE_DATA = 3
STATE_CLOSE = 4

class Client(jsocket.JsonClient):
    def __init__(self, address="127.0.0.1", port=5000, file_name):
        super(Client, self).__init__(address, port)

        self.file_name = file_name

        self.algorithm = None
        self.mode = None
        self.hash_function = None
        self.iv = None
        self.protocols = {
            'algorithms': ['3DES', 'AES'],
            'modes': ['ECB', 'CBC'],
            'hash_function': ['SHA-256', 'MD5'],
        }

        self.key = None
        self.private_key = None
        self.public_key = None

    def do_connect(self):
        """
            Connect to server

        """

        self.connect()
        logger.debug("Connected to server")

        self.send({"type": "CONNECT"})
        data = self.read()
    
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'OK':
            logger.debug("Connection failed!!")
            raise Exception("Error from server")

        # Do stuff
        
        self.state = STATE_KEYEX
        #TODO: negociar!

    def do_agreement(self) -> None:
        #TODO: Por agora, a negociação é aleatória
        self.algorithm = self.protocols.get('algorithms')[random.randint(0,1)]
        self.mode = self.protocols.get('modes')[random.randint(0,1)]
        self.hash_function = self.protocols.get('hash_function')[random.randint(0,1)]

        if self.algorithm == 'AES':
            self.iv = os.urandom(16)
        elif self.algorithm == '3DES':
            self.iv = os.urandom(8)

        msg = {'type': 'AGREEMENT',
					'algorithm': self.algorithm,
					'mode': self.mode,
					'hash_function': self.hash_function,
					'iv' : base64.b64encode(self.iv).decode('utf-8')}

        self.send(msg)


    def do_keyexchange(self):
        """
            Exchange keys with server in order to secure the communication
            Further communications may use the keys to secure all content

        """
    
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'OK':
            raise Exception("Error from server")

        data = self.read()

    def do_authenticate(self) -> None:
        """
            Send server an authentication request
            May need to obtain user credentials
        """

        self.send({"type": "AUTHN"})
        data = self.read()
    
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'OK':
            raise Exception("Error from server")

        # Do stuff

    def do_authorize(self) -> None:
        """
            Send server an authorization request

        """

        self.send({"type": "AUTHZ"})
        data = self.read()
    
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'OK':
            raise Exception("Error from server")

        # Do stuff

    def get_file(self, file_name: str) -> None:
        """
            Gets a file from the server

            :param file_name: The name of the file to get
        """
        self.send({"type": "GET", "file_name": file_name})
        data = self.read()
        
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'OK':
            raise Exception("Error from server")

        data = self.read()
        
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'DATA':
            raise Exception("Error from server")

        logger.info("Got file: {}".format(file_name))
        payload = binascii.a2b_base64(data.get('payload', None))
        
        with open(file_name, "wb") as f:
            f.write(payload)

        # Do stuff

    def send(self, message: dict) -> None:
        """
            Sends a message to the server
            :param message: The message to send

        """

        logger.debug("Send: {}".format(message))

        # Encrypt, adapt, etc... 

        return self.send_obj(message)


    def read(self) -> dict:
        """
            Reads a message from the server
            :param message: Waits for a message from the server
        """

        data = self.read_obj()
        logger.debug("Got: {}".format(data))
        
        # Decrypt, filter, etc..

        mtype = data.get('type', 'UNKNOWN')
        if mtype == 'ERROR':
            raise Exception("Error from server")

        return data

    def encrypt(self, message: dict) -> dict:
        """
            Encrypt a message
            
            :param message: Message to encrypt
        """
        cipher = None
        block_size = 0
        backend = default_backend()

        # Encrypt
        # Algorithm
        if self.algorithm == 'AES':
            alg = algorithms.AES(self.key)
            block_size = alg.block_size
        elif self.algorithm == '3DES':
            alg = algorithms.3DES(self.key)
            block_size = alg.block_size

        # Mode
        if self.mode == 'ECB':
            modo = modes.ECB()
        elif self.mode == 'CBC':
            modo = modes.CBC(self.iv)
        cipher = Cipher(alg, modo, backend=default_backend())

        # Synthesis
        if self.synthesis == 'SHA-256':
            sintese = hashes.SHA256()
        elif self.synthesis == 'MD5':
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

    def decrypt(self, message: dict) -> dict:
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
        payload = message.get('payload')
        text, h_mac = payload
        # TODO: duplicação de código. CHECK THIS
        # Algorithm
        if self.algorithm == 'AES':
            alg = algorithms.AES(self.key)
            block_size = alg.block_size
        elif self.algorithm == '3DES':
            alg = algorithms.3DES(self.key)
            block_size = alg.block_size

        # Mode
        if self.mode == 'ECB':
            modo = modes.ECB()
        elif self.mode == 'CBC':
            modo = modes.CBC(self.iv)
        cipher = Cipher(alg, modo, backend=default_backend())

        # Synthesis
        if self.synthesis == 'SHA-256':
            sintese = hashes.SHA256()
        elif self.synthesis == 'MD5':
            sintese = hashes.MD5()

        # Decrypt msg
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(block_size).unpadder()
        h = hmac.HMAC(self.key, sintese, backend=default_backend())
        h.update(text)
        h.verify(h_mac)
        p_data = decryptor.update(text) + decryptor.finalize()
        data = unpadder.update(p_data) + unpadder.finalize()
        final_data = base64.b64decode(data)
        return final_data


    def verify_integrity_control(self, message: dict) -> bool:
        """
            Verify the message integrity control
        
            :param message: A SECURE message
        """

        return True

    def add_integrity_control(self, message: dict) -> dict:
        """
            Verify the message integrity control

            :param message: A SECURE message
        """

        return message


def main():
    parser = argparse.ArgumentParser(description='Gets files from servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, action='store', dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, action='store',
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to get')

    args = parser.parse_args()
    file_name = args.file_name
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    try:
        logger.info("Connecting to server.\n- Address: {}\n- Port: {}".format(server, port))
        client = Client(address=server, port=port)
        client.do_connect()
        client.do_keyexchange()
        client.do_authenticate()
        client.do_authorize()
        logger.info("Connected")
    except:
        logger.exception("Server connect")
        return

    try:
        logger.info("Getting file from server: {}".format(file_name))
        client.get_file(file_name)
    except:
        logger.exception("File transfer")

    client.close()

if __name__ == '__main__':
    main()