# This Python file uses the following encoding: utf-8
import os, subprocess, time, requests, threading

from http.server import BaseHTTPRequestHandler, HTTPServer


class HttpGetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open("detectedMessages", "a") as f:
            f.write(self.path[1:]+"\n")


class TorClient:
    def __init__(self, root):
        # Запуск Tor
        self.tor_proc = subprocess.Popen(["tor", "-f", "torConfig"])
        time.sleep(60)
        self.hostname = "error"
        for i in range(20):
            try:
                self.hostname = open(os.path.join("hidden_service", "hostname"), "r").read().rstrip()[:-6]
                break
            except:
                time.sleep(1)
        if self.hostname == "error":
            print("Error: Hostname не найден")
            self.tor_proc.kill()
            exit()
        # Создание сессии
        self.session = requests.session()
        #self.session.proxies = {'http': 'socks5://127.0.0.1:9050', 'https': 'socks5://127.0.0.1:9050'}
        # Запуск принимающего сервера
        self.httpd = HTTPServer(('127.0.0.1', 9051), HttpGetHandler)
        threading.Thread(target=lambda: self.startGetRequestsDaemon(root), args=()).start()
        time.sleep(10)

    def doRequest(self, address, request):
        # Отправка запроса на сервер
        return self.session.get('http://' + address + '.onion/' + request, proxies={'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'})

    def startGetRequestsDaemon(self, root):
        # Запуск HTTP сервера
        self.httpd.serve_forever()


    def stop(self):
        # Остановка процессов
        self.httpd.server_close()
        self.tor_proc.kill()
