#!/usr/bin/python

import time, struct

import logging.config
from mixConfig import getRemailerConfig
from mixMath import *


_mixMsgDatabase = None
def getMsgDatabase():
    global _mixMsgDatabase
    if not _mixMsgDatabase:
        _mixMsgDatabase = MixMsgDatabase()

    return _mixMsgDatabase

class MixMsgDatabaseEntry():
    def __init__(self):
        pass
    def getBinaryString(self):
        return self.Identifier + struct.pack("i", self.DayStored)
    @staticmethod
    def from_binary(binary):
        ret = MixMsgDatabaseEntry()
        ret.Identifier = binary[:16]
        ret.PrintableIdentifier = hexpad(bigEndian(binaryToByteArray(ret.Identifier)), 32)
        ret.DayStored = struct.unpack("i", binary[16:20])[0]
        return ret
    @staticmethod
    def from_parts(msgid, daystored):
        ret = MixMsgDatabaseEntry()
        if isinstance(msgid, str):
            ret.Identifier = msgid
            ret.PrintableIdentifier = hexpad(bigEndian(binaryToByteArray(ret.Identifier)), 32)
        elif isinstance(msgid, long):
            ret.Identifier = struct.pack(">IIII", int(msgid >> 96), int((msgid >> 64) & 0xFFFFFFFF), int((msgid >> 32) & 0xFFFFFFFF), int(msgid & 0xFFFFFFFF))
            ret.PrintableIdentifier = hexpad(msgid, 32)
        else:
            raise Exception("Got unexpected type " + type(msgid) + " in from_parts")
        ret.DayStored = int(daystored)
        return ret
    
class MixMsgDatabase():
    _day = 24 * 60 * 60
    _database = {}
    def _getFileHandle(self, mode="rb"):
        try:
            f = open(getRemailerConfig('filelocations')['iddatabase'], mode)
        except IOError:
            f = open('../../' + getRemailerConfig('filelocations')['iddatabase'], mode)
        return f
    def __init__(self):
        self._database = {}
        
        f = self._getFileHandle()
        bstr = f.read(20)
        while bstr:
            entry = MixMsgDatabaseEntry.from_binary(bstr)
            self._database[entry.Identifier] = entry
            bstr = f.read(20)
        f.close()
        
    def _writeNewDatabase(self):
        pass
        #_newDatabase = {}
        #for e in self._database:
        #    if self._database[e].DayStored > something:
        #        _newDatabase[e] = self._database[e]
        #replace, write new file
    def isDuplicate(self, msgid):
        return msgid in self._database
    def addMessage(self, msgid):
        now = time.time()
        today = now - (now % self._day)
        
        entry = MixMsgDatabaseEntry.from_parts(msgid, today)
        self._database[msgid] = entry
        
        f = self._getFileHandle("ab")
        f.write(entry.getBinaryString())
        f.close()
    def pprint(self):
        for e in self._database:
            print "\t", time.ctime(self._database[e].DayStored), self._database[e].PrintableIdentifier
        

if __name__ == "__main__":
    logging.config.fileConfig("../../config/test_logging.conf")
    import random
    msgid = "".join(chr(random.randrange(0, 256)) for i in xrange(16))
    getMsgDatabase().addMessage(msgid)
    getMsgDatabase().isDuplicate(msgid)
    #getMsgDatabase().pprint()
        
    
