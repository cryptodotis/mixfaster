#!/usr/bin/python

import logging, logging.config

from mixKey import *
from mixConfig import getRemailerConfig

_mixKeyStore = None
def getKeyStore():
    global _mixKeyStore
    if not _mixKeyStore:
        _mixKeyStore = MixKeyStore()
        
        f = open(getRemailerConfig()['filelocations']['secring.mix'], 'r')
        privateKeyLines = f.readlines()
        f.close()
        _mixKeyStore.addKey(privateKeyLines, getRemailerConfig('remailerkeypassword'))
        
        f = open(getRemailerConfig()['filelocations']['pubring.mix'], 'r')
        lines = f.readlines()
        f.close()
        key = []
        for l in lines:
            l = l.strip()
            if l == "-----End Mix Key-----":
                key.append(l)
                _mixKeyStore.addKey(key)
                key = []
            else:
                key.append(l)
        
    return _mixKeyStore

class MixKeyStore:
    keystore = {}
    def __init__(self):
        pass
    def addKey(self, keylines, passphrase=""):
        key = parseMixKey(keylines, passphrase)

        if key.KeyId in self.keystore:
            if isinstance(self.keystore[key.KeyId], PublicMixKey) and isinstance(key, PrivateMixKey):
                logging.info("Replacing Public Key " + key.KeyId + " in self.keystore with Private Key")
                key.loadPublicCapabilitys(self.keystore[key.KeyId])
                self.keystore[key.KeyId] = key
            else:
                logging.info("Not Replacing Key " + key.KeyId + " in self.keystore with new key")
        else:
            self.keystore[key.KeyId] = key
            logging.info("Adding Key " + key.KeyId + " to self.keystore")
    def getKey(self, keyid):
        if keyid in self.keystore:
            return self.keystore[keyid]
        else:
            return None
    def getPublicKey(self, keyid):
        if keyid in self.keystore and isinstance(self.keystore[keyid], PrivateMixKey):
            return self.keystore[keyid].getPublicMixKey()
        elif keyid in self.keystore and isinstance(self.keystore[keyid], PublicMixKey):
            return self.keystore[keyid]
        else:
            return None
    def getPrivateKey(self, keyid):
        if keyid in self.keystore and isinstance(self.keystore[keyid], PrivateMixKey):
            return self.keystore[keyid]
        else:
            return None
    def listPrivateKeys(self):
        a = []
        for k in self.keystore:
            if isinstance(self.keystore[k], PrivateMixKey):
                a.append(k)
        return a

if __name__ == "__main__":
    logging.config.fileConfig("../../config/test_logging.conf")
    print str(getKeyStore().listPrivateKeys())