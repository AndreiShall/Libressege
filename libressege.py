# This Python file uses the following encoding: utf-8
from PyQt5 import QtWidgets, uic

from Tor import TorClient

import sys


class Ui(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui, self).__init__()
        uic.loadUi("Libressege.ui", self)
        self.findChild(QtWidgets.QPushButton, "newDialogButton").clicked.connect(self.openNewDialogForm)
        self.findChild(QtWidgets.QPushButton, "openSettingsButton").clicked.connect(self.openSettingsForm)

    def openNewDialogForm(self):
        form = uic.loadUi("NewDialogForm.ui")
        form.findChild(QtWidgets.QPushButton, "cancel").clicked.connect(form.close)
        form.findChild(QtWidgets.QPushButton, "ok").clicked.connect(form.close)
        form.findChild(QtWidgets.QPushButton, "ok").clicked.connect(lambda: self.newDialog(form.findChild(QtWidgets.QLineEdit, "id").text(), form.findChild(QtWidgets.QTextEdit, "publicKey").toPlainText()))
        form.show()

    def openSettingsForm(self):
        form = uic.loadUi("SettingsForm.ui")
        form.show()

    def newDialog(self, ID, publicKey):
        l = QtWidgets.QVBoxLayout(self)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(0)
        w = uic.loadUi("DialogWidget.ui")
        w.findChild(QtWidgets.QLabel, "idView").setText(ID)
        l.addWidget(w)
        self.findChild(QtWidgets.QWidget, "dialogsView").setLayout(l)

    def getNewMessage(self, message):
        print(message)


if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    window = Ui()
    #window.show()
    #sys.exit(app.exec_())
    t = TorClient(window)
    try:
        t.doRequest("endrnfiru6hpc6itssau5tv7xbjp5sjvbmw4qcgd3hqayp53x2bamrid","hi")
        t.stop()
    except Exception as error:
        t.stop()
        print("Error:")
        print(error)
