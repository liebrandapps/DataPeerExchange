'''
  Mark Liebrand 2023
  This file is part of DataPeerExchange which is released under the Apache 2.0 License
  See file LICENSE or go to for full license details https://github.com/liebrandapps/DataPeerExchange
'''

import io


class SockIOException(Exception):
    pass


class SockIOData:
    typeString = 1
    typeNumber = 2
    typeCommand = 3
    typeBinary = 4
    typeLongDirect = 64


class SockWrite(SockIOData):
    '''
    classdocs
    '''

    def __init__(self):
        pass

    def writeString(self, key, value, byteIO):
        byteIO.write(chr(SockIOData.typeString))
        self.__writeRawString(key, byteIO)
        self.__writeRawString(value, byteIO)

    def __writeRawString(self, strg, strgIO):
        length = len(strg)
        hiByte = int(abs(length / 256))
        loByte = length % 256
        strgIO.write(chr(hiByte))
        strgIO.write(chr(loByte))
        strgIO.write(strg)

    def writeLongDirect(self, value, bytesIO):
        Byte0 = int(abs(value / 16777216))
        value = value % 16777216
        Byte1 = int(abs(value / 65536))
        value = value % 65536
        Byte2 = int(abs(value / 256))
        Byte3 = int(value % 256)
        bytesIO.write(bytes([Byte0, Byte1, Byte2, Byte3]))

    def writeBinaryDirect(self, value, strgIO):
        strgIO.write(value)

    def writeBinary(self, key, value, strgIO):
        strgIO.write(chr(SockIOData.typeBinary))
        self.__writeRawString(key, strgIO)
        ln = len(value)
        Byte0 = int(abs(ln / 16777216))
        ln = ln % 16777216
        Byte1 = int(abs(ln / 65536))
        ln = ln % 65536
        Byte2 = int(abs(ln / 256))
        Byte3 = ln % 256
        strgIO.write(chr(Byte0))
        strgIO.write(chr(Byte1))
        strgIO.write(chr(Byte2))
        strgIO.write(chr(Byte3))
        strgIO.write(value)

    def writeLong(self, key, value, strgIO):
        strgIO.write(chr(SockIOData.typeNumber))
        self.__writeRawString(key, strgIO)
        Byte0 = abs(value / 16777216)
        value = value % 16777216
        Byte1 = abs(value / 65536)
        value = value % 65536
        Byte2 = abs(value / 256)
        Byte3 = value % 256
        strgIO.write(chr(Byte0))
        strgIO.write(chr(Byte1))
        strgIO.write(chr(Byte2))
        strgIO.write(chr(Byte3))


class SockRead(SockIOData):

    ###
    # Returns a tuple
    # dataType, key, value
    def read(self, strgIO):
        tmp = strgIO.read(1)
        if len(tmp) == 0:
            raise SockIOException()
        typ = ord(tmp)
        key, value = {SockIOData.typeString: lambda: (self.__readRawString(strgIO), self.__readRawString(strgIO)),
                      SockIOData.typeNumber: lambda: (self.__readRawString(strgIO), self.__readRawLong(strgIO)),
                      SockIOData.typeBinary: lambda: (self.__readRawString(strgIO), self.__readRawBinary(strgIO)),
                      SockIOData.typeLongDirect: lambda: ("", self.__readRawLong(strgIO))
                      }[typ]()
        return (typ, key, value)

    def __readRawString(self, strgIO):
        hiByte = ord(strgIO.read(1))
        loByte = ord(strgIO.read(1))
        length = (hiByte << 8) + loByte
        strg = strgIO.read(length)
        return (strg)

    def __readRawLong(self, bytesIO):
        byte0 = bytesIO.read(1)
        byte1 = bytesIO.read(1)
        byte2 = bytesIO.read(1)
        byte3 = bytesIO.read(1)
        value = (byte0 * 16777216) + (byte1 * 65536) + (byte2 * 256) + byte3
        return value

    def readRawLong(self, arr):
        byte0 = arr[0]
        byte1 = arr[1]
        byte2 = arr[2]
        byte3 = arr[3]
        value = (byte0 * 16777216) + (byte1 * 65536) + (byte2 * 256) + byte3
        return value

    def __readRawBinary(self, strgIO):
        length = self.__readRawLong(strgIO)
        binary = strgIO.read(length)
        return binary


class ReadDictionary:

    def __init__(self):
        pass

    def read(self, data):
        d = {}
        sockRd = SockRead()
        buf = io.BytesIO(data)
        try:
            while True:
                _, key, value = sockRd.read(buf)
                d[key] = value
        except SockIOException:
            pass
        buf.close()
        return d


class WriteDictionary:

    def write(self, data):
        sockWt = SockWrite()
        buf = io.BytesIO(data)
        for k in data.keys:
            if type(data[k]) is int:
                sockWt.writeLong(k, data[k], buf)
            if type(data[k]) is str:
                sockWt.writeString(k, data[k], buf)
            if type(data[k] is dict):
                sockWt.writeBinary(k, WriteDictionary.write(data[k]), buf)
