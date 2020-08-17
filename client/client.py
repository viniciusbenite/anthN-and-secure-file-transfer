import jsocket
import coloredlogs, logging
import binascii
import argparse

logger = logging.getLogger('jclient')

class Client(jsocket.JsonClient):
    def __init__(self, address="127.0.0.1", port=5000):
        super(Client, self).__init__(address, port)


    def do_connect(self):
        """
            Connect to server

        """

        self.connect()

        self.send({"type": "CONNECT"})
        data = self.read()
    
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'OK':
            raise Exception("Error from server")

        # Do stuff


    def do_keyexchange(self):
        """
            Exchange keys with server in order to secure the communication
            Further communications may use the keys to secure all content

        """
        self.send({"type": "KEYEX"})
        data = self.read()
    
        mtype = data.get('type', 'UNKNOWN')
        if mtype != 'OK':
            raise Exception("Error from server")
        # Do stuff

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
        # Encrypt  message and convert to base64
        message = {'type': 'SECURE', 'payload': message}
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

        return message.get('payload')


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