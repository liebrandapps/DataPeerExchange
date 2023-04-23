import base64
import datetime
import glob
import io
import json
import os
import secrets
import socket
from pathlib import Path

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA

from myio.liebrand.dpex.utility import ReadDictionary, SockRead, SockWrite


class Sender:
    OP_INIT = "init"
    OP_ADD = "add"
    PRIVATE_KEY = "id_rsa"
    PUBLIC_KEY = "id_rsa.pub"

    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log

    def op(self, op, data=None):
        if op == Sender.OP_INIT:
            self.log.info("Initialising...")
            self.getKey()
            self.log.info("Done")

        if op == Sender.OP_ADD:
            self.addClient(data)

    def getKey(self):
        keyDir = self.cfg.general_serverKeyDir
        if not (os.path.isdir(keyDir)):
            os.mkdir(keyDir)
        privKeyFile = os.path.join(keyDir, Sender.PRIVATE_KEY)
        publicKeyFile = os.path.join(keyDir, Sender.PUBLIC_KEY)

        if os.path.exists(privKeyFile):
            self.log.info(f"Private key file exists ({privKeyFile}), no need to generate")
            with open(privKeyFile) as fp:
                keydata = fp.read()
            key = RSA.importKey(keydata)
        else:
            self.log.info(
                f"Private key does not file exist ({privKeyFile}), please be patient - going to need a while to generate a key.")
            key = RSA.generate(self.cfg.general_keyBits)
            self.log.info("Done with key generation, saving keys.")
            with open(privKeyFile, 'wb') as fp:
                fp.write(key.exportKey('PEM'))
            if os.path.exists(publicKeyFile):
                os.remove(publicKeyFile)

        if not (os.path.exists(publicKeyFile)):
            with(open(publicKeyFile, 'wb')) as fp:
                key.public_key().exportKey('OpenSSH')
        return key

    def addClient(self, data):
        rsp = {}
        encrsp = {}
        key = self.getKey()
        aesKey = secrets.token_bytes(32)
        magicHeader = secrets.token_bytes(8)

        clientUid = data['uid']
        clientPublicKeyStrg = data['publicKey']

        clientWorkDir = os.path.join(self.cfg.general_clientRoot, clientUid)
        clientPublicKeyFile = os.path.join(clientWorkDir, "id_rsa.pub")
        clientConfigFile = os.path.join(clientWorkDir, 'client.cfg')
        if not (os.path.exists(self.cfg.general_clientRoot)):
            os.mkdir(self.cfg.general_clientRoot)
        if not (os.path.exists(clientWorkDir)):
            os.mkdir(clientWorkDir)
        if os.path.exists(clientPublicKeyFile):
            os.remove(clientPublicKeyFile)
        pK = base64.b64decode(clientPublicKeyStrg)
        publicKey = RSA.importKey(pK)
        with(open(clientPublicKeyFile, 'wb')) as fp:
            fp.write(publicKey.exportKey('OpenSSH'))

        outgoingDir = os.path.join(clientWorkDir, "outgoing")
        if not (os.path.isdir(outgoingDir)):
            os.mkdir(outgoingDir)

        rsp['publicKey'] = base64.b64encode(key.public_key().exportKey()).decode('UTF-8')
        encrsp['host'] = self.cfg.general_serverHost
        encrsp['port'] = self.cfg.general_serverPort
        encrsp['aes'] = aesKey.hex()
        encrsp['aesCreation'] = datetime.datetime.now().timestamp()
        encrsp['magicHeader'] = magicHeader.hex()

        with(open(clientConfigFile, 'w')) as fp:
            json.dump(encrsp, fp)

        strgToEncrypt = json.dumps(encrsp)
        clientPubKey = PKCS1_OAEP.new(publicKey)
        enc = clientPubKey.encrypt(strgToEncrypt.encode('UTF-8'))
        rsp['encData'] = base64.b64encode(enc).decode('UTF-8')

        print("Send the following json to your client:")
        print(json.dumps(rsp))

    def serve(self):
        self.log.info("Starting server")
        clients = self.loadClientConfigs()
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serverSocket.bind(('0.0.0.0', 4488))
        while True:
            msg, addr = serverSocket.recvfrom(1024)
            if len(msg) < 33:
                continue
            for c in clients.values():
                match = True
                for idx in range(8):
                    if msg[idx] != c['magicHeaderBytes'][idx]:
                        match = False
                        break
                if match:
                    break
            if not match:
                continue
            iv = msg[8:24]
            sockRd = SockRead()
            length = sockRd.readRawLong(msg[24:28])
            aesCreation = sockRd.readRawLong(msg[28:32])
            encData = msg[32:32 + length]
            key = bytes.fromhex(c['aes'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decData = cipher.decrypt(encData)
            BS = 16
            unpad = lambda s: s[:-ord(s[len(s) - 1:])]
            raw = unpad(decData)
            req = json.loads(raw)
            rsp = {}
            if req['op'] == 'ls':
                root = self.cfg.general_clientRoot
                files = glob.glob(c['outgoing'] + "/*")
                print(files)
                list = {}
                for f in files:
                    baseFName = os.path.basename(f)
                    stat = Path(f).stat()
                    info = {'size': stat.st_size, 'mtime': stat.st_mtime}
                    list[baseFName] = info
                strg = json.dumps(list)
                bts = strg.encode('UTF-8')
                pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode('UTF-8')
                raw = pad(bts)
                iv = Random.new().read(AES.block_size)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                cipherText = cipher.encrypt(raw)
                sockWt = SockWrite()
                buffer = io.BytesIO()
                buffer.write(iv)
                sockWt.writeLongDirect(len(cipherText), buffer)
                buffer.write(cipherText)
                serverSocket.sendto(buffer.getbuffer(), addr)

        self.log.info("Terminating server")

    def loadClientConfigs(self):
        clients = {}
        dir = self.cfg.general_clientRoot
        for (dirpath, dirnames, filenames) in os.walk(dir):
            for dirName in dirnames:
                clientCfgFile = os.path.join(dirpath, dirName, 'client.cfg')
                clientPubKey = os.path.join(dirpath, dirName, 'id_rsa.pub')
                with open(clientCfgFile) as fp:
                    data = json.load(fp)
                with open(clientPubKey) as fp:
                    keydata = fp.read()
                data['clientKey'] = keydata
                data['magicHeaderBytes'] = bytes.fromhex(data['magicHeader'])
                data['outgoing'] = os.path.join(dirpath, dirName, 'outgoing')
                clients[dirName] = data
            break
        return clients
