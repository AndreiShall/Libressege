from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

from base64 import b64encode, b64decode

from http.server import BaseHTTPRequestHandler, HTTPServer

from os.path import join

import requests, threading, os, json

from PyQt5 import QtCore, QtGui, QtWidgets
import sys


class HttpGetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open("messages", "w") as f:
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
        self.session = requests.session()
        self.session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        x = threading.Thread(target=self.getMessage, args=())
        y = threading.Thread(target=self.readMessage, args=())
        x.start()
        y.start()

    def getMessage(self, server_class=HTTPServer, handler_class=HttpGetHandler):
        server_address = ('127.0.0.1', 9090)
        httpd = server_class(server_address, handler_class)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()

    def readMessage(self):
        while True:
            try:
                with open("messages", "r") as f:
                    messageJSON = json.loads(self.crypto.decrypt(f.read()))
                    if os.path.exists(join(os.getcwd(), messageJSON["senderAddress"])):
                        with open(messageJSON["senderAddress"], "a") as ff:
                            ff.write(messageJSON["message"] + "\n")
                    else:
                        with open(messageJSON["senderAddress"], "2") as ff:
                            ff.write(messageJSON["senderPublicKey"] + "\n")
                            ff.write(messageJSON["message"] + "\n")
            except:
                pass

    def sendMessage(self, address, message, publicKey):
        try:
            self.session.get('http://' + address + '.onion/' + self.crypto.encrypt(json.dumps({"message": message, "senderAddress": "", "senderPublicKey": self.crypto.getKey()}), publicKey))
        except:
            pass


class Cryptography():
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

class Ui_Libressege(object):
    def setupUi(self, Libressege):
        Libressege.setObjectName("Libressege")
        Libressege.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(Libressege)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)
        self.centralwidget.setStyleSheet("background-color: rgb(0, 68, 69);")
        self.centralwidget.setObjectName("centralwidget")
        self.dialogsView = QtWidgets.QWidget(self.centralwidget)
        self.dialogsView.setGeometry(QtCore.QRect(20, 20, 200, 560))
        self.dialogsView.setStyleSheet("background-color: rgb(2, 28, 30);\n"
"border-radius:20px;")
        self.dialogsView.setLocale(QtCore.QLocale(QtCore.QLocale.Russian, QtCore.QLocale.Russia))
        self.dialogsView.setObjectName("dialogsView")
        self.addressView = QtWidgets.QWidget(self.dialogsView)
        self.addressView.setGeometry(QtCore.QRect(0, 0, 200, 50))
        self.addressView.setStyleSheet("background-color: rgb(44, 120, 115);\n"
"border-radius: 20px;\n"
"border-bottom-left-radius: 0px;\n"
"border-bottom-right-radius: 0px;")
        self.addressView.setObjectName("addressView")
        self.label = QtWidgets.QLabel(self.addressView)
        self.label.setGeometry(QtCore.QRect(20, 15, 160, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setText("")
        self.label.setObjectName("label")
        self.dialogsList = QtWidgets.QListWidget(self.dialogsView)
        self.dialogsList.setGeometry(QtCore.QRect(0, 50, 200, 460))
        self.dialogsList.setObjectName("dialogsList")
        self.newDialogButtonArea = QtWidgets.QWidget(self.dialogsView)
        self.newDialogButtonArea.setGeometry(QtCore.QRect(0, 510, 200, 50))
        self.newDialogButtonArea.setStyleSheet("background-color: rgb(44, 120, 115);\n"
"border-radius: 20px;\n"
"border-top-left-radius: 0px;\n"
"border-top-right-radius: 0px;")
        self.newDialogButtonArea.setObjectName("newDialogButtonArea")
        self.newDialogButton = QtWidgets.QPushButton(self.newDialogButtonArea)
        self.newDialogButton.setGeometry(QtCore.QRect(20, 10, 160, 30))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        font.setStrikeOut(False)
        font.setKerning(True)
        font.setStyleStrategy(QtGui.QFont.PreferDefault)
        self.newDialogButton.setFont(font)
        self.newDialogButton.setAutoFillBackground(False)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("images/newDialog.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.newDialogButton.setIcon(icon)
        self.newDialogButton.setIconSize(QtCore.QSize(32, 32))
        self.newDialogButton.setCheckable(False)
        self.newDialogButton.setChecked(False)
        self.newDialogButton.setAutoRepeat(False)
        self.newDialogButton.setAutoExclusive(False)
        self.newDialogButton.setDefault(False)
        self.newDialogButton.setFlat(False)
        self.newDialogButton.setObjectName("newDialogButton")
        self.dialogView = QtWidgets.QWidget(self.centralwidget)
        self.dialogView.setGeometry(QtCore.QRect(240, 20, 540, 560))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.dialogView.sizePolicy().hasHeightForWidth())
        self.dialogView.setSizePolicy(sizePolicy)
        self.dialogView.setStyleSheet("background-color: rgb(2, 28, 30);\n"
"border-radius:20px;")
        self.dialogView.setObjectName("dialogView")
        self.recipientAddressView = QtWidgets.QWidget(self.dialogView)
        self.recipientAddressView.setGeometry(QtCore.QRect(0, 0, 540, 50))
        self.recipientAddressView.setStyleSheet("background-color: rgb(44, 120, 115);\n"
"border-radius: 20px;\n"
"border-bottom-left-radius: 0px;\n"
"border-bottom-right-radius: 0px;")
        self.recipientAddressView.setObjectName("recipientAddressView")
        self.recipientAddressLabel = QtWidgets.QLabel(self.recipientAddressView)
        self.recipientAddressLabel.setGeometry(QtCore.QRect(20, 15, 500, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.recipientAddressLabel.setFont(font)
        self.recipientAddressLabel.setText("")
        self.recipientAddressLabel.setObjectName("recipientAddressLabel")
        self.MessageArea = QtWidgets.QWidget(self.dialogView)
        self.MessageArea.setGeometry(QtCore.QRect(0, 510, 540, 50))
        self.MessageArea.setStyleSheet("background-color: rgb(44, 120, 115);\n"
"border-radius: 20px;\n"
"border-top-left-radius: 0px;\n"
"border-top-right-radius: 0px;")
        self.MessageArea.setObjectName("MessageArea")
        self.messageInput = QtWidgets.QLineEdit(self.MessageArea)
        self.messageInput.setGeometry(QtCore.QRect(20, 10, 450, 30))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.messageInput.setFont(font)
        self.messageInput.setInputMask("")
        self.messageInput.setObjectName("messageInput")
        self.sendButton = QtWidgets.QPushButton(self.MessageArea)
        self.sendButton.setGeometry(QtCore.QRect(490, 10, 30, 30))
        self.sendButton.setStatusTip("")
        self.sendButton.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("images/sendButton.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.sendButton.setIcon(icon1)
        self.sendButton.setIconSize(QtCore.QSize(32, 32))
        self.sendButton.setFlat(False)
        self.sendButton.setObjectName("sendButton")
        self.dialogList = QtWidgets.QListWidget(self.dialogView)
        self.dialogList.setGeometry(QtCore.QRect(0, 50, 540, 460))
        self.dialogList.setObjectName("dialogList")
        self.newDialogDialog = QtWidgets.QDialog(self.centralwidget)
        self.newDialogDialog.setGeometry(QtCore.QRect(10, 10, 300, 150))
        self.newDialogDialog.setStyleSheet("background-color: rgb(44, 120, 115);")
        self.newDialogDialog.setModal(False)
        self.newDialogDialog.setObjectName("newDialogDialog")
        self.closeNewDialogDialogButton = QtWidgets.QPushButton(self.newDialogDialog)
        self.closeNewDialogDialogButton.setGeometry(QtCore.QRect(160, 110, 120, 30))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.closeNewDialogDialogButton.setFont(font)
        self.closeNewDialogDialogButton.setObjectName("closeNewDialogDialogButton")
        self.createNewDialogButton = QtWidgets.QPushButton(self.newDialogDialog)
        self.createNewDialogButton.setGeometry(QtCore.QRect(20, 110, 120, 30))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.createNewDialogButton.setFont(font)
        self.createNewDialogButton.setObjectName("createNewDialogButton")
        self.recipientAddressInput = QtWidgets.QLineEdit(self.newDialogDialog)
        self.recipientAddressInput.setGeometry(QtCore.QRect(20, 10, 260, 30))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.recipientAddressInput.setFont(font)
        self.recipientAddressInput.setObjectName("recipientAddressInput")
        self.recipientPublicKeyInput = QtWidgets.QLineEdit(self.newDialogDialog)
        self.recipientPublicKeyInput.setGeometry(QtCore.QRect(20, 60, 260, 30))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.recipientPublicKeyInput.setFont(font)
        self.recipientPublicKeyInput.setObjectName("recipientPublicKeyInput")
        Libressege.setCentralWidget(self.centralwidget)

        self.retranslateUi(Libressege)

        self.newDialogButton.clicked.connect(self.newDialogDialog.exec)
        self.closeNewDialogDialogButton.clicked.connect(self.newDialogDialog.close)
        self.createNewDialogButton.clicked.connect(self.newDialog)
        self.sendButton.clicked.connect(self.newMessage)
        self.dialogsList.itemClicked.connect(self.viewDialog)

        self.updateDialogsList()

        QtCore.QMetaObject.connectSlotsByName(Libressege)

    def retranslateUi(self, Libressege):
        _translate = QtCore.QCoreApplication.translate
        Libressege.setWindowTitle(_translate("Libressege", "Libressege"))
        self.newDialogDialog.setWindowTitle(_translate("Libressege", "Новый диалог"))
        self.newDialogButton.setText(_translate("Libressege", "  Hачать диалог"))
        self.messageInput.setPlaceholderText(_translate("Libressege", "Сообщeние..."))
        self.closeNewDialogDialogButton.setText(_translate("Libressege", "Закрыть"))
        self.createNewDialogButton.setText(_translate("Libressege", "Hачать диалог"))
        self.recipientAddressInput.setPlaceholderText(_translate("Libressege", "Адрес получателя..."))
        self.recipientPublicKeyInput.setPlaceholderText(_translate("Libressege", "Публичный ключ получателя..."))

    def newDialog(self):
        try:
            f = open(join(join(os.getcwd(), "dialogs"), self.recipientAddressInput.text()), "w")
        except FileNotFoundError:
            os.mkdir("dialogs")
            f = open(join(join(os.getcwd(), "dialogs"), self.recipientAddressInput.text()), "w")
        f.write(self.recipientPublicKeyInput.text())
        f.close()
        self.recipientAddressInput.setText("")
        self.recipientPublicKeyInput.setText("")
        self.newDialogDialog.close()
        self.updateDialogsList()

    def updateDialogsList(self):
        self.dialogsList.clear()
        try:
            for filename in os.listdir(join(os.getcwd(), "dialogs")):
                item = QtWidgets.QListWidgetItem(filename)
                self.dialogsList.addItem(item)
        except FileNotFoundError:
            os.mkdir("dialogs")
        self.dialogsList.update()

    def viewDialog(self, item):
        self.recipientAddressLabel.setText(item.text())
        self.updateMessagesList()

    def newMessage(self):
        if self.recipientAddressLabel.text() != "":
            f = open(join(join(os.getcwd(), "dialogs"), self.recipientAddressLabel.text()), "a")
            f.write("\n" + self.messageInput.text())
            f.close()
            self.messageInput.setText("")
            self.updateMessagesList()

    def updateMessagesList(self):
        self.dialogList.clear()
        f = open(join(join(os.getcwd(), "dialogs"), self.recipientAddressLabel.text()), "r")
        messages = f.readlines()[1:]
        f.close()
        for message in messages:
            item = QtWidgets.QListWidgetItem(message)
            self.dialogList.addItem(item)
        self.dialogList.update()

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    Libressege = QtWidgets.QMainWindow()
    ui = Ui_Libressege()
    ui.setupUi(Libressege)
    Libressege.show()
    sys.exit(app.exec_())