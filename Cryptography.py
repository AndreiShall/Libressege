# This Python file uses the following encoding: utf-8
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

from base64 import b64encode, b64decode

from os.path import join

class Cryptography:
    def __init__(self, dataDir):
        self.dataDir = dataDir

    def generateKey(self, code="code"):
        key = RSA.generate(2048)
        self.privateKeyRSA = key.exportKey(passphrase=code, pkcs=8, protection="scryptAndAES128-CBC")
        self.publicKeyRSA = key.publickey().exportKey()

    def exportKeys(self):
        with open(join(self.dataDir, 'privateKey.bin'), 'wb') as f:
            f.write(self.privateKeyRSA)

        with open(join(self.dataDir, 'publicKey.pem'), 'wb') as f:
            f.write(self.publicKeyRSA)

    def importKeys(self, code="code"):
        self.privateKeyRSA = RSA.import_key(open(join(self.dataDir, 'privateKey.bin')).read(), passphrase=code)
        self.publicKeyRSA = RSA.import_key(open(join(self.dataDir, 'publicKey.pem')).read())

    def encrypt(self, data, publicKeyRSA):
        session_key = get_random_bytes(16)
        try:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(publicKeyRSA.replace('\\n', "\n")))
        except:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(publicKeyRSA))
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(str(data).encode("utf8"))
        data = cipher_rsa.encrypt(session_key) + cipher_aes.nonce + tag + ciphertext
        return b64encode(data).decode('utf-8')

    def decrypt(self, data):
        enc_session_key, nonce, tag, ciphertext = (b64decode(data)[:self.privateKeyRSA.size_in_bytes()],
                                                   b64decode(data)[
                                                   self.privateKeyRSA.size_in_bytes():self.privateKeyRSA.size_in_bytes() + 16],
                                                   b64decode(data)[
                                                   self.privateKeyRSA.size_in_bytes() + 16:self.privateKeyRSA.size_in_bytes() + 32],
                                                   b64decode(data)[self.privateKeyRSA.size_in_bytes() + 32:])
        cipher_rsa = PKCS1_OAEP.new(self.privateKeyRSA)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode("utf8")

    def getKey(self):
        try:
            return str(self.publicKeyRSA.export_key("PEM"))[2:-1]
        except:
            return str(self.publicKeyRSA)[2:-1]
