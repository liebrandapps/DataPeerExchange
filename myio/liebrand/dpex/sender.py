'''
  Mark Liebrand 2023
  This file is part of DataPeerExchange which is released under the Apache 2.0 License
  See file LICENSE or go to for full license details https://github.com/liebrandapps/DataPeerExchange
'''

import base64
import datetime
import glob
import io
import json
import os
import secrets
import socket
import time
from pathlib import Path

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA

from myio.liebrand.dpex.fileholder import FileHolderServer
from myio.liebrand.dpex.utility import SockRead, SockWrite


class Sender:
    OP_INIT = "init"
    OP_ADD = "add"
    PRIVATE_KEY = "id_rsa"
    PUBLIC_KEY = "id_rsa.pub"
    BS = 16
    pad = lambda s: s + (Sender.BS - len(s) % Sender.BS) * chr(Sender.BS - len(s) % Sender.BS).encode('UTF-8')

    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.timePerChunk = None
        self.delay = 0.0
        self.sndCnt = 0
        self.rcvCnt = 0

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
            with (open(publicKeyFile, 'wb')) as fp:
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
        with (open(clientPublicKeyFile, 'wb')) as fp:
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
        serverSocket.bind(('0.0.0.0', self.cfg.general_serverPort))
        serverSocket.settimeout(1.0)
        while True:
            try:
                msg, addr = serverSocket.recvfrom(1024)
            except socket.timeout:
                for c in clients.values():
                    if c['getinProgress']:
                        key = bytes.fromhex(c['aes'])
                        self.processget(key, c, serverSocket, addr, c['file'])
                continue
            match = False
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
            unpad = lambda s: s[:-ord(s[len(s) - 1:])]
            raw = unpad(decData)
            req = json.loads(raw)
            if req['op'] == 'ls':
                self.processls(key, c, serverSocket, addr)
            if req['op'] == 'get':
                c['clientSize'] = req['clientSize']
                self.processget(key, c, serverSocket, addr, req['file'])
            if req['op'] == 'ack':
                self.rcvCnt += 1
                self.processack(key, c, serverSocket, addr, req['ack'], req['nxt'])
                if 'perf' in req.keys() and self.timePerChunk is not None:
                    # print(f"Time per Chunk on Server {self.timePerChunk}, on Client {req['perf']}")
                    if self.timePerChunk < (req['perf'] + 25):
                        self.delay += 25
                    else:
                        self.delay -= 25
                        if self.delay < 0:
                            self.delay = 0

        self.log.info("Terminating server")

    def processls(self, key, c, serverSocket, addr):
        self.log.info("Processing command 'ls'")
        files = glob.glob(c['outgoing'] + "/*")
        list = {}
        for f in files:
            baseFName = os.path.basename(f)
            stat = Path(f).stat()
            info = {'size': stat.st_size, 'mtime': stat.st_mtime}
            list[baseFName] = info
        self.sendEncryptedResponse(list, key, serverSocket, addr)

    def processget(self, key, c, serverSocket, addr, fileName):
        logInfo = False
        path = os.path.join(c['outgoing'], fileName)
        if not c['getinProgress']:
            self.log.info("Processing command 'get'")
            logInfo = True
            if not os.path.exists(path):
                dta = {'status': 'fail', 'msg': f"File '{fileName}' does not exist"}
                self.sendEncryptedResponse(dta, key, serverSocket, addr, useRaw=True)
                self.log.warn(dta['msg'])
                return
            else:
                fileSize = os.path.getsize(path)
                if fileSize == c['clientSize']:
                    dta = {'status': 'fail', 'msg': f"File '{fileName}' exists with full size in local directory (or has size zero)"}
                    self.sendEncryptedResponse(dta, key, serverSocket, addr, useRaw=True)
                    self.log.warn(dta['msg'])
                    return
                else:
                    c['getinProgress'] = True
                    c['file'] = fileName
                    c['fileHolder'] = FileHolderServer(path, c['clientSize'], fileSize, self.cfg, self.log)
                    c['sndCnt'] = 0
        fileSize = os.path.getsize(path)
        fileHolder = c['fileHolder']
        dta = {'status': 'ok', 'op': "chunk"}
        estChunkCount = int((fileSize - c['clientSize']) / self.cfg.general_chunkSize)
        if logInfo:
            c['estChunkCount'] = estChunkCount
            if c['clientSize'] == 0:
                self.log.debug(f"Sending file {path} with size {fileSize} in {estChunkCount} pieces.")
            else:
                self.log.debug(f"Resuming file {path} with remaining size {dta['totalSize']-c['clientSize']} in {estChunkCount} pieces.")
        if fileHolder.reachedTimeout():
            self.log.error("Client disappeared, cancelling transmission")
            c['getinProgress'] = False
            del c['file']
            del c['fileHolder']
            return
        interval = 0
        start = datetime.datetime.now()
        self.delay = 0
        while interval < 100:
            nxt, chunk = fileHolder.getNextPart()
            if nxt is None:
                c['getinProgress'] = False
                del c['file']
                del c['fileHolder']
                self.log.debug(f"Done with sending file {path}, actual pieces {c['estChunkCount']}, transferred {c['sndCnt']}")
                break
            dta['idx'] = nxt
            self.sndCnt += 1
            if interval == 0:
                dta['totalSize'] = fileSize
                dta['sndCnt'] = self.sndCnt
                dta['rcvCnt'] = self.rcvCnt
                if fileHolder.md5sum is not None:
                    dta['md5'] = fileHolder.md5sum
            strg = json.dumps(dta)
            bts = strg.encode('UTF-8')
            sockWt = SockWrite()
            buffer = io.BytesIO()
            sockWt.writeLongDirect(len(bts), buffer)
            buffer.write(bts)
            buffer.write(chunk)
            raw = Sender.pad(buffer.getbuffer().tobytes())
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipherText = cipher.encrypt(raw)
            sockWt = SockWrite()
            buffer = io.BytesIO()
            buffer.write(iv)
            sockWt.writeLongDirect(len(cipherText), buffer)
            buffer.write(cipherText)
            serverSocket.sendto(buffer.getbuffer(), addr)
            c['sndCnt'] += 1
            interval += 1
            if self.delay > 0.0:
                time.sleep(self.delay / 1000000)
        if interval != 0:
            self.timePerChunk = (datetime.datetime.now() - start).microseconds / interval
        else:
            self.timePerChunk = None

        # self.log.debug(f"Send {interval} chunks to {addr}")

    def processack(self, key, c, serverSocket, addr, ack, nxtIdx):
        # self.log.debug("processAck")
        if not c['getinProgress']:
            return
        fileHolder = c['fileHolder']
        fileHolder.ack(ack, nxtIdx)
        self.processget(key, c, serverSocket, addr, c['file'])

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
                data['getinProgress'] = False
                clients[dirName] = data
            break
        return clients

    @staticmethod
    def sendEncryptedResponse(jsonData, key, serverSocket, addr, useRaw=False):
        sockWt = SockWrite()
        strg = json.dumps(jsonData)
        bts = strg.encode('UTF-8')
        if useRaw:
            buffer = io.BytesIO()
            sockWt.writeLongDirect(len(bts), buffer)
            buffer.write(bts)
            raw = Sender.pad(buffer.getbuffer().tobytes())
        else:
            raw = Sender.pad(bts)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipherText = cipher.encrypt(raw)
        buffer = io.BytesIO()
        buffer.write(iv)
        sockWt.writeLongDirect(len(cipherText), buffer)
        buffer.write(cipherText)
        serverSocket.sendto(buffer.getbuffer(), addr)
