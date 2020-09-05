import jsocket
import coloredlogs
import logging
import binascii
import argparse
import json
import random
import os
import base64
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as padder
from cryptography import x509

logger = logging.getLogger('jclient')

# Static vars
STATE_CONNECT = 0  # Cliend Just Connected
STATE_KEYEX = 1  # Key Exchange
STATE_AUTHN = 3  # AUTHeNtication
STATE_AUTHZ = 3  # AUTHoriZation
STATE_GET = 4  # Data Transfer
STATE_AGREEMENT = 5


class Client(jsocket.JsonClient):
    def __init__(self, auth_mode, address="127.0.0.1", port=5000):
        super(Client, self).__init__(address, port)

        self.auth_mode = auth_mode # Pass only
        self.server_crt = {}

        self.algorithm = None
        self.mode = None
        self.hash_function = None
        self.iv = None
        self.protocols = {
            'algorithms': ['3DES', 'AES'],
            'modes': ['ECB', 'CBC'],
            'hash_functions': ['SHA-256', 'MD5'],
        }

        self.key = None
        self.private_key = None
        self.public_key = None
        
        self.sv_crt_pub_key = None

        self.rsa_pub_key = None
        self.rsa_pri_key = None

    def do_connect(self):
        """
            Function to connect to server. After successfull conection, start
            algorithms agreement and key exchange.
        """

        self.connect()
        logger.debug("Trying to connect to server")
        logger.debug("Mode {}".format(self.mode))
        self.send({"type": "CONNECT"})

        data = self.read()
        logger.debug("CONNECT got -> {}".format(data))
        mtype = data.get('type', 'UNKNOWN')

        if mtype != 'CONNECT_OK':
            logger.debug("Connection failed!!")
            raise Exception("Error from server")

        # Do stuff
        self.state = STATE_AGREEMENT
        # negociar!
        self.do_agreement()

    def do_agreement(self) -> None:
        """
            Function to define algorithms, hash functions and modes.
            Those are defined randomly.
        """

        self.algorithm = self.protocols.get('algorithms')[random.randint(0, 1)]
        self.mode = self.protocols.get('modes')[random.randint(0, 1)]
        self.hash_function = self.protocols.get('hash_functions')[random.randint(0, 1)]

        if self.algorithm == 'AES':
            self.iv = os.urandom(16)
        elif self.algorithm == '3DES':
            self.iv = os.urandom(8)

        msg = {'type': 'AGREEMENT',
					'algorithm': self.algorithm,
					'mode': self.mode,
					'hash_functions': self.hash_function,
					'iv': base64.b64encode(self.iv).decode('utf-8')}

        self.send(msg)

        self.state = STATE_KEYEX

    def do_keyexchange(self):
        """
            Exchange keys with server in order to secure the communication
            Further communications may use the keys to secure all content

        """
        logger.info("STATE: KEYEX")

		# do key exchange
        params = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

        # Private key
        self.private_key = params.generate_private_key()

        # Public key
        self.public_key = self.private_key.public_key()

        public_key_bytes = self.public_key.public_bytes(serialization.Encoding.DER,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo)

        # Prime numbers
        p = params.parameter_numbers().p
        g = params.parameter_numbers().g

        msg = {'type': 'KEYEX',
        'public_key': base64.b64encode(public_key_bytes).decode('utf-8'),
        'p': p,
        'g': g}
        self.send(msg)

        data = self.read()
        logger.debug("KEYEX got -> {}".format(data))
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'AGREEMENT_OK':
            raise Exception("MSG != SERVER_PUBLIC_KEY")
        
        # Advance state
        logger.info("Advancing to STATE_AUTHN")
        self.state = STATE_AUTHN

    def do_authenticate(self) -> None:
        """
            Send server an authentication request
            May need to obtain user credentials
            User may choose authenticate by password or CC
        """
        logger.info("Begining authn process")

        # Gen key
        d = self.read()

        b_server_pub_key = base64.b64decode(d['server_public_key'])
        server_pub_key = serialization.load_der_public_key(b_server_pub_key, backend=default_backend())
        shared_key = self.private_key.exchange(server_pub_key)

        # Derivation
        self.key = HKDF(algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'derivation',
        backend=default_backend()).derive(shared_key)

        # Send authentication request
        self.server_nonce = os.urandom(16)
        text = str.encode(json.dumps({ "type": 'AUTHN_REQ', "nonce": base64.b64encode(self.server_nonce).decode('utf-8') }))
        payload, mac = self.encrypt(text)
        msg = { "type": 'SECURE', "payload": base64.b64encode(payload).decode('utf-8'), "h_mac": base64.b64encode(mac).decode('utf-8') }
        self.send(msg)

        # Authenticate server
        data = self.read()
        logger.debug("KEY_GEN got -> {}".format(data))
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'KEY_GEN_OK':
            raise Exception("Something went wrong in key gen")
        
        sv_nonce = base64.b64decode(data["nonce"])
        b_sv_crt = base64.b64decode(data["sv_cert"])
        self.sv_crt = x509.load_der_x509_certificate(b_sv_crt, backend=default_backend())

        with open("./certs/rootCA.crt", "rb") as f:
            data = f.read()
            self.rootCA_crt = x509.load_pem_x509_certificate(data, backend=default_backend())

        self.sv_crt_pub_key = self.sv_crt.public_key()
        self.rootCA_crt_pub_key = self.rootCA_crt.public_key()

        hs = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hs.update(self.server_nonce)
        digest = hs.finalize()

        # Verify the signature validation
        try:
            self.sv_crt_pub_key.verify(sv_nonce, digest, padder.PSS(mgf=padder.MGF1(hashes.SHA256()), salt_length=padder.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))
            logger.info("Server authenticated")
        except Exception as e:
            #TODO fix this ... DONE!
            logger.exception("Invalid signature {}".format(e))
            exit(1)
            
        #TODO VALIDATE SERVER CHAIN ???
        

        if self.auth_mode == "pass":
                self.password_validation_request()
        else:
            self.send({ "type": "ERROR" })
            raise Exception("Authentication mode not suported")

        # Check if authentication went ok
        p_reply = self.read()
        logger.info(p_reply)
        logger.debug("AUTHN got -> {}".format(p_reply))
        mtype = p_reply.get('type', 'UNKNOWN')
        if mtype != 'AUTHN_OK':
            raise Exception("Authentication fail!!")

        logger.info("Advancing state")
        self.state = STATE_AUTHZ

    def do_authorize(self) -> None:
        """
            Send server an authorization request

        """
        text = str.encode(json.dumps( { "type": "AUTHZ_REQ", "user": self.user }))
        payload, mac = self.encrypt(text)
        msg = { "type": "SECURE", "payload": base64.b64encode(payload).decode("utf-8"), "h_mac": base64.b64encode(mac).decode("utf-8") }
        self.send(msg)
        
        data = self.read()
        logger.debug("AUTHZ got -> {}".format(data))
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'GET_OK':
            raise Exception("Authorization failed")
        logger.info("Advancing state")
        self.state = STATE_GET

    def get_file(self, file_name: str) -> None:
        """
            Gets a file from the server

            :param file_name: The name of the file to get
        """
        text = str.encode(json.dumps( { "type": "FILE_REQ", "file_name": file_name }))
        #TODO codigo dupli.. refactor!
        payload, mac = self.encrypt(text)
        msg = { "type": "SECURE", "payload": base64.b64encode(payload).decode("utf-8"), "h_mac": base64.b64encode(mac).decode("utf-8") }
        self.send(msg)

        data = self.read()

        mtype = data.get('type', 'UNKNOWN')
        logger.debug("GET FILE GOT -> {}".format(data))
        if mtype != 'DOWNLOAD_OK':
            raise Exception("Error from server")

        data = self.read()

        mtype = data.get('type', 'UNKNOWN')
        logger.debug("GET FILE GOT -> {}".format(data))
        if mtype != 'DATA':
            raise Exception("Error from server")

        logger.info("Got file: {}".format(file_name))
        payload = binascii.a2b_base64(data.get('payload', None))

        with open(file_name, "wb") as f:
            f.write(payload)

    def send(self, message: dict) -> None:
        """
            Sends a message to the server
            :param message: The message to send

        """
        try:
            logger.debug("Send: {}".format(message))
        except Exception as e:
            logger.exception("Exception -> {}".format(e))
        msg = (json.dumps(message, indent=4))
        self.send_obj(msg)

    def read(self) -> dict:
        """
            Reads a message from the server
            :param message: Waits for a message from the server
        """
        try:
            data = self.read_obj()
            d = json.loads(data)
            if d['type'] == 'SECURE':
                logger.debug("We got a secure msg")
                payload = base64.b64decode(d['payload'])
                h_mac = base64.b64decode(d['h_mac'])
                dd = self.decrypt(payload, h_mac, d)
                dec_data = json.loads(dd)
                return dec_data
        except Exception as e:
            logger.exception("WTF is going on? -> {}".format(e))

        mtype = d.get('type', 'UNKNOWN')
        if mtype == 'ERROR':
            logger.exception(d.get("payload"))
            raise Exception(d.get('payload'))

        return d

    def encrypt(self, message: dict) -> dict:
        """
            Encrypt a message
            
            :param message: Message to encrypt
        """
        cipher = None
        block_size = 0

        # Encrypt ...

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
        
        # Integrity control
        h_mac = self.add_integrity_control(text, sintese)

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
        if self.verify_integrity_control(text, sintese, mac) is False:
            raise Exception ("Integrity control failed")
        p_data = decryptor.update(text) + decryptor.finalize()
        data = unpadder.update(p_data) + unpadder.finalize()
        final_data = base64.b64decode(data)
        return final_data


    def verify_integrity_control(self, text, sintese, mac):
        """
            Verify the message integrity control
        
            :param message: A SECURE message
        """
        try:
            h = hmac.HMAC(self.key, sintese, backend=default_backend())
            h.update(text)
            h.verify(mac)
        except Exception as e:
            logger.exception("Integrity control failed -> {}".format(e))
            return False

        return True

    def add_integrity_control(self, text, sintese):
        """
            Add message integrity control

            :param message: A SECURE message
        """
        h = hmac.HMAC(self.key, sintese, backend=default_backend())
        h.update(text)
        h_mac = h.finalize()

        return h_mac

    # Auxiliar functions
    def password_validation_request(self):
        """
            Function to send a password challenge request to server.
        """
        logger.info("REQUESTING PASSWORD CHALLENGE")
        self.rsa_pri_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.rsa_pub_key = self.rsa_pri_key.public_key()
        b_rsa_pub_key = self.rsa_pub_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        text = str.encode(json.dumps({ "type": "PWD_CHALLENGE_REQ", "RSA_PUB_KEY": base64.b64encode(b_rsa_pub_key).decode("utf-8") }))
        payload, mac = self.encrypt(text)
        msg = { "type": "SECURE", "payload": base64.b64encode(payload).decode("utf-8"), "h_mac": base64.b64encode(mac).decode("utf-8") }
        self.send(msg)

        try:
            reply = self.read()
            mtype = reply.get("type")
            if mtype == "CHALLENGE_PASS":
                self.password_validation_reply(reply)
        except Exception as e:
            logger.exception("Something went wrong ... {}".format(e))

    def password_validation_reply(self, message: str) -> None:
        """
            Function to reply to the challenge sended by the server.
            :param message: the challenge sended by server
        """
        logger.info("REPLYING PASSWORD CHALLENGE")
        self.chalange_nonce = base64.b64decode(message["nonce"])
        self.user = input("Type you name: ")
        pwd = input("Type your password: ")
        p = pwd.encode() + self.chalange_nonce
        hs = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hs.update(p)
        digest = hs.finalize()
        pass_signed = self.rsa_pri_key.sign(digest, padder.PSS(mgf=padder.MGF1(hashes.SHA256()), salt_length=padder.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))
        text = str.encode(json.dumps( { "type": "CHALLENGE_PWD_REP", "user": self.user, "password": base64.b64encode(pass_signed).decode("utf-8") }))
        payload, mac = self.encrypt(text)
        msg = { "type": "SECURE", "payload": base64.b64encode(payload).decode("utf-8"), "h_mac": base64.b64encode(mac).decode("utf-8") }
        self.send(msg)

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
    parser.add_argument('-m', dest='auth_mode', help="Choose the authN method(pass or cc) ")

    args = parser.parse_args()
    file_name = args.file_name
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server
    auth_mode = args.auth_mode

    coloredlogs.install(level)
    logger.setLevel(level)

    try:
        logger.info("Connecting to server.\n- Address: {}\n- Port: {}".format(server, port))
        client = Client(auth_mode=auth_mode, address=server, port=port)
        client.do_connect()
        client.do_keyexchange()
        client.do_authenticate()
        client.do_authorize()
        logger.info("Connected")
    except:
        logger.exception("Server disconnect")
        return

    try:
        logger.info("Getting file from server: {}".format(file_name))
        client.get_file(file_name)
    except:
        logger.exception("File transfer")

    client.close()

if __name__ == '__main__':
    main()
