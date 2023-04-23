import base64
import datetime
import io
import json
import os
import sys
import uuid
import socket

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA

from myio.liebrand.dpex.utility import SockWrite, SockRead


class Receiver:
    PRIVATE_KEY = "id_rsa"
    PUBLIC_KEY = "id_rsa.pub"
    CONFIG = "./dpex.cfg"

    OP_INIT = "init"
    OP_UPDATE = "update"
    OP_LS = "ls"

    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log

    def op(self, op, data=None):
        if op == Receiver.OP_INIT:
            key = self.getKey()
            uid = self.getUID()
            dct = {}
            dct['uid'] = uid
            dct['publicKey'] = base64.b64encode(key.public_key().exportKey()).decode('UTF-8')
            strg = json.dumps(dct)
            print("Send the following json (e.g. via mail) to the provider of the server")
            print(strg)

        if op == Receiver.OP_UPDATE:
            self.update(data)

        if op == Receiver.OP_LS:
            self.ls()

    def getKey(self):
        if not (os.path.isdir(self.cfg.general_exchangeKeyDir)):
            os.mkdir(self.cfg.general_exchangeKeyDir)
        privKeyFile = os.path.join(self.cfg.general_exchangeKeyDir, Receiver.PRIVATE_KEY)
        publicKeyFile = os.path.join(self.cfg.general_exchangeKeyDir, Receiver.PUBLIC_KEY)

        if os.path.exists(privKeyFile):
            self.log.info(f"Private key file exists ({privKeyFile}), no need to generate")
            with open(privKeyFile) as fp:
                keydata = fp.read()
            key = RSA.importKey(keydata)
        else:
            self.log.info(
                f"Private key does not file exist ({privKeyFile}), please be patient - going to need a while to "
                f"generate a key.")
            key = RSA.generate(self.cfg.general_keyBits)
            self.log.info("Done with key generation, saving keys.")
            with open(privKeyFile, 'wb') as fp:
                fp.write(key.exportKey('PEM'))
            if os.path.exists(publicKeyFile):
                os.remove(publicKeyFile)

        if not (os.path.exists(publicKeyFile)):
            with(open(publicKeyFile, 'wb')) as fp:
                fp.write(key.public_key().exportKey('OpenSSH'))
        return key

    def getUID(self):
        uidFile = self.cfg.general_uidFile
        if os.path.exists(uidFile):
            with open(uidFile) as fp:
                myuuid = fp.read()
                myuuid = myuuid.rstrip()
        else:
            myuuid = str(uuid.uuid4())
            with open(uidFile, "w") as fp:
                fp.write(myuuid)
        return myuuid

    def update(self, data):
        self.log.info("Creating config for server based on received data.")
        serverPublicKeyStrg = data["publicKey"]
        encData = data['encData']
        cfgData = {}
        cfgData['serverPublicKey'] = serverPublicKeyStrg
        key = self.getKey()
        bytes = base64.b64decode(encData)
        privKey = PKCS1_OAEP.new(key)
        enc = privKey.decrypt(bytes)
        strg = enc.decode('UTF-8')
        clearData = json.loads(strg)
        cfgData['host'] = clearData['host']
        cfgData['port'] = clearData['port']
        cfgData['aes'] = clearData['aes']
        cfgData['aesCreation'] = clearData['aesCreation']
        cfgData['magicHeader'] = clearData['magicHeader']
        with open(Receiver.CONFIG, "w") as fp:
            json.dump(cfgData, fp)
        self.log.info(
            f"Download server is at {cfgData['host']}:{cfgData['port']}, receiver AES Key for communication, query "
            f"available files with 'client.py ls")
        self.log.info(f"Config is stored in {Receiver.CONFIG}")

    def ls(self):
        self.log.info("Requesting list of files")
        if not (os.path.exists(Receiver.CONFIG)):
            self.log.error(
                f"Config file {Receiver.CONFIG} does not exist, need to run client.py update <received server.json> "
                f"first.")
            sys.exit(-1)

        with open(Receiver.CONFIG) as fp:
            cfgData = json.load(fp)

        key = bytes.fromhex(cfgData['aes'])
        encData = {'op': "ls", 'ts': datetime.datetime.now().timestamp()}
        strg = json.dumps(encData)
        bts = strg.encode('UTF-8')
        BS = 16
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode('UTF-8')
        raw = pad(bts)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipherText = cipher.encrypt(raw)
        magicHeaderBytes = bytes.fromhex(cfgData['magicHeader'])
        sockWt = SockWrite()
        buffer = io.BytesIO()
        buffer.write(magicHeaderBytes)
        buffer.write(iv)
        sockWt.writeLongDirect(len(cipherText), buffer)
        sockWt.writeLongDirect(cfgData['aesCreation'], buffer)
        buffer.write(cipherText)
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSocket.settimeout(3.0)
        addr = (cfgData['host'], cfgData['port'])
        clientSocket.sendto(buffer.getbuffer(), addr)
        try:
            msg, addr = clientSocket.recvfrom(1024)
        except socket.timeout:
            self.log.error("Server did not respond")
            return
        sockRd = SockRead()
        iv = msg[:16]
        length = sockRd.readRawLong(msg[16:20])
        cipherText = msg[20:20+length]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        bts = cipher.decrypt(cipherText)
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        raw = unpad(bts)
        rsp = json.loads(raw)
        self.log.info("==================================================")
        for f in rsp.keys():
            fData = rsp[f]
            dt = datetime.datetime.fromtimestamp(fData['mtime'])
            self.log.info(f"{fData['size']:10} {dt:%b %d} {f}")
        self.log.info("==================================================")
        self.log.info("Done requesting list of files")