import json
import binascii
import argparse
import coloredlogs, logging
import jsocket
import copy
import base64
import os
import random
import string
import json
import re
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger('jserver')

# Static vars
STATE_CONNECT = 0 # Cliend Just Connected
STATE_KEYEX   = 1 # Key Exchange
STATE_AUTHN   = 3 # AUTHeNtication
STATE_AUTHZ   = 3 # AUTHoriZation
STATE_GET    = 4 # Data Transfer
STATE_AGREEMENT = 5

#GLOBAL
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
		self.synthesis = None
		self.iv = None
		self.protocols = {
			'algorithms': ['3DES', 'AES'],
			'modes': ['ECB', 'CBC'],
			'synthesis': ['MD5', 'SHA-256']
		}

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
			message = self.process_secure(message)

		if message is not None:
			mtype = message.get('type', "").upper()
			if mtype == 'CONNECT':
				ret = self.process_connect(message)
			elif mtype == 'KEYEX':
				ret = self.process_keyex(message)
			elif mtype == 'AUTHN':
				ret = self.process_authn(message)
			elif mtype == 'AUTHZ':
				ret = self.process_authz(message)
			elif mtype == 'GET':
				ret = self.process_get(message)
			else:
				logger.warning("Invalid message type: {}".format(message['type']))

		if not ret:
			try:
				self.send({'type': 'ERROR', 'message': 'See server and restart the process'})
			except:
				pass # Silently ignore

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

		self.send({'type': 'OK'})
		self.state = STATE_KEYEX
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
		if message['synthesis'] not in self.protocols['synthesis']:
			logger.info('synthesis not found!')
			return False
		self.synthesis = message["synthesis"]
		
		# Definir iv
		self.iv = base64.b64decode(message['iv'])

		logger.info(
			f'algoritmo: {self.algorithm}, modo: {self.mode}, sintese: {self.synthesis}, iv:{self.iv}')
		message = {'type': 'AGREEMENT_OK'}
		self._send(message)
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

		self.send({'type': 'OK'})
		# In the last message of this process advance the state
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


		self.send({'type': 'OK'})
		# In the last message of this process advance the state
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
		# TODO: NOTHING TO BE DONE HERE!
		logger.debug("Send: {}".format(json.dumps(message, indent=4)))
		self.send_obj(message)

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

	logger.info("Starting.\n- Port: {}\n- LogLevel: {}\n- Storage: {}".format(port, level, storage_dir))
	
	jserver = jsocket.ServerFactory(ServerFactoryThread, address='0.0.0.0', port=port)
	jserver.timeout = 2
	jserver.start()

if __name__ == '__main__':
	main()


