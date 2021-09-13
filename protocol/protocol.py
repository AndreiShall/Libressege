from protocol.Cryptography.Cryptography import Cryptography
import requests, threading, os
from http.server import BaseHTTPRequestHandler, HTTPServer

class HttpGetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open("messages", "a") as f: 
            f.write(str(self.path[1:]))

class Protocol():
    def __init__(self):
        self.crypto = Cryptography(os.getcwd())

    def start(self):
        try:
            self.crypto.importKeys()
        except:
            self.crypto.generateKey()
            self.crypto.exportKeys()
        x = threading.Thread(target=self.getMessage, args=())
        x.start()
        self.session = requests.session()
        self.session.proxies = {'http':  'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}

    def getMessage(self, server_class=HTTPServer, handler_class=HttpGetHandler):
        server_address = ('127.0.0.1', 9090)
        httpd = server_class(server_address, handler_class)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()

    def readMessage(self):
        message = ""
        with open("messages", "r") as f:
            messageJSON = (self.crypto.decrypt(f.readline()))
            message, senderAddress, senderPublicKey = (messageJSON["message"], messageJSON["senderAddress"], messageJSON["senderPublicKey"])
        return (message, senderAddress, senderPublicKey)

    def sendMessage(self, address, message, publicKey):
        try:
            self.session.get('http://' + address + '.onion/' + {"message": self.crypto.encrypt(message, publicKey), "senderAddress": "", "senderPublicKey": self.crypto.getKey()})
        except:
            pass
