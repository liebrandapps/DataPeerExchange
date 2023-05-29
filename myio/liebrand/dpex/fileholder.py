"""
  Mark Liebrand 2023
  This file is part of DataPeerExchange which is released under the Apache 2.0 License
  See file LICENSE or go to for full license details https://github.com/liebrandapps/DataPeerExchange
"""
import datetime
import os.path


class FileHolderClient:
    COLLECT_COUNT = 10000

    def __init__(self, fileName):
        self.fileName = fileName
        self.pieces = {}
        self.ack = []
        self.counter = FileHolderClient.COLLECT_COUNT
        self.writeIndex = 0
        self.totalSize = 0
        self.lastSize = -1
        self.datedCount = 0
        self.effPos = 0
        self.chunkSize = 0

    def addChunk(self, index, chunk, totalSize=None):
        if totalSize is not None:
            self.totalSize = totalSize
        if not (index < self.writeIndex):
            self.pieces[index] = chunk
            self.chunkSize = len(chunk)
        else:
            self.datedCount += 1
        self.ack.append(index)
        self.counter -= 1
        if self.counter == 0 or index == self.writeIndex:
            self.check()

    def check(self):
        idx = self.writeIndex
        while idx in self.pieces.keys():
            idx += 1
        if idx != self.writeIndex:
            with open(self.fileName, 'ab') as fp:
                i = self.writeIndex
                while i < idx:
                    fp.write(self.pieces[i])
                    self.effPos += len(self.pieces[i])
                    del self.pieces[i]
                    i += 1
            self.writeIndex = idx
            self.lastSize = os.path.getsize(self.fileName)
            if self.counter == 0:
                print(
                    f"Length of writeout queue {len(self.pieces.keys())}, next piece {self.writeIndex}, dated pieces {self.datedCount}")
            self.datedCount = 0
        self.counter = FileHolderClient.COLLECT_COUNT

    def isComplete(self):
        return self.totalSize == self.lastSize

    def getAck(self):
        return self.ack

    def clearAck(self):
        self.ack = []

    def getWrittenToDisk(self):
        return int(self.effPos / self.totalSize * 100)

    def getKeptInMemory(self):
        return int((self.chunkSize * len(self.pieces.keys())) / self.totalSize * 100)


class FileHolderServer:

    def __init__(self, fileName, effectivePos, fileSize, cfg, log):
        self.fileName = fileName
        self.cfg = cfg
        self.log = log
        self.pos = 0
        self.pieces = {}
        self.queue = []
        self.chunkSize = self.cfg.general_chunkSize
        self.effPos = effectivePos
        self.lastAck = None
        self.fileSize = fileSize
        self.requestedNext = None

    def fillPieces(self):
        if len(self.queue) > int(self.cfg.general_maxChunks / 2):
            return
        if self.effPos == self.fileSize:
            return
        needed = self.cfg.general_maxChunks - len(self.pieces.keys())
        with open(self.fileName, "rb") as fp:
            fp.seek(self.effPos, 0)
            while needed > 0:
                chunk = fp.read(self.chunkSize)
                if len(chunk) == 0:
                    break
                self.pieces[self.pos] = chunk
                self.queue.append(self.pos)
                self.pos += 1
                needed -= 1
                self.effPos += len(chunk)

    def ack(self, ackData, nxtIdx):
        self.lastAck = datetime.datetime.now()
        for a in ackData:
            if a in self.pieces.keys():
                del self.pieces[a]
            if a in self.queue:
                self.queue.remove(a)
        tmp = []
        for x in self.queue:
            if x < nxtIdx:
                tmp.append(x)
        for x in tmp:
            self.queue.remove(x)
            del self.pieces[x]
        if nxtIdx in self.queue:
            self.requestedNext = nxtIdx
        self.fillPieces()

    def getNextPart(self):
        self.fillPieces()
        if len(self.queue) == 0:
            return None, None
        if self.requestedNext is None or self.requestedNext not in self.queue:
            nxt = self.queue.pop(0)
            self.queue.append(nxt)
        else:
            nxt = next((x for x in self.queue if x == self.requestedNext), None)
            self.requestedNext = None
        return nxt, self.pieces[nxt]

    def reachedTimeout(self):
        if self.lastAck is None:
            return False
        elapsed = (datetime.datetime.now() - self.lastAck).total_seconds()
        return elapsed > self.cfg.general_timeout
