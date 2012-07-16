#!/usr/bin/python

import sys, struct, time
import hashlib
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from base64 import *

import logging, logging.config
from mixMath import *

def parseMixKey(lines, passphrase=""):
    class State:
        CapLine = 1
        Header = 2
        Body = 3
    if isinstance(lines, str) or isinstance(lines, unicode):
        lines = lines.split("\n")

    state = State.CapLine
    for l in lines:
        l = l.strip()
        
        if not l: 
            continue
        elif l == "-----Begin Mix Key-----":
            if state == State.CapLine or state == State.Header:
                state = State.Body
            else:
                raise Exception("Got the key header when I wasn't expecting it")
        elif "Created" in l:
            if state == State.Body:
                key = PrivateMixKey(lines, passphrase)
                break
            else:
                raise Exception("Got the key body when I wasn't expecting it")
        elif len(l) == 32: #Assume PubKey
            if state == State.Body:
                key = PublicMixKey(lines)
                break
            else:
                raise Exception("Got the key body when I wasn't expecting it")
        elif state == State.CapLine:
            capline = l
            state = State.Header
        else:
            raise Exception("Could not parse key as public or private Mix Key:", l)
    return key

class PublicMixKey:
    class State:
        NoState = 0
        CapLine = 1
        Header = 2
        KeyID = 3
        Length = 4
        Key = 5
        Footer = 6
        Done = 7
    KeyId = 0
    KeyLen = 0
    KeyVal = ""
    KeyVal_Decoded = 0
    Decoded_KeyLen = 0
    N = 0
    E = 0
    def __init__(self, lines=[]):
        state = self.State.CapLine
        
        for l in lines:
           l = l.strip()
           
           if not l: continue
           elif l == "-----Begin Mix Key-----":
               if state != self.State.Header:
                   print lines
                   raise Exception("Found Header when wasn't expecting it")
               else:
                   state = self.State.KeyID
           elif state == self.State.CapLine:
                self.CapLine = l
                state = self.State.Header
           elif state == self.State.KeyID:
               self.KeyId = l
               state = self.State.Length
           elif state == self.State.Length:
               self.KeyLen = l
               state = self.State.Key
           elif l == "-----End Mix Key-----":
               if state != self.State.Key:
                   raise Exception("Found Footer when wasn't expecting it")
               else:
                   state = self.State.Done
           elif state == self.State.Key:
               self.KeyVal += l
           else:
               raise Exception("Got Non-Blank Line that doesn't fit.")
        if lines:          
            self.decode()
    def decode(self):
        try:
            peices = self.CapLine.split()
        except AttributeError:
            raise Exception("Could not parse Public Key without a CapLine:", self.KeyId)
        
        self.ShortName = peices[0]
        self.Address = peices[1]
        otherKeyId = peices[2]
        if otherKeyId != self.KeyId:
            raise Exception("Key IDs don't match.")
    
        temp = peices[3].partition(":")
        if temp[2]:
            self.Protocol = temp[0]
            self.Version = temp[2]
        else:
            self.Version = temp[0]
            self.Protocol = "2" #Assume
        
        if len(peices) > 4:
            temp = peices[4]
        else:
            temp = ""
        self.Middleman = "M" in temp
        self.Compress = "C" in temp
        self.News = temp.replace("M", "").replace("C", "")
            
     
        self.KeyVal_Decoded = b64decode(self.KeyVal)
        if len(self.KeyVal_Decoded) != 258:
            raise Exception("KeyLength is non-standard")
        
        bytes128 = 'B' * 128
        
        self.Decoded_KeyLen = struct.unpack('<H', self.KeyVal_Decoded[0:2])[0]  #Unsigned Short, Little Endian
        self.N = bigEndian(struct.unpack('>' + bytes128, self.KeyVal_Decoded[2:130])) #128 Bytes
        self.E = bigEndian(struct.unpack('>' + bytes128, self.KeyVal_Decoded[130:]))  #128 Bytes
    
    PublicRSAKey = None
    def getPCPublicKey(self):
        if not self.PublicRSAKey:
            self.PublicRSAKey = RSA.construct((long(self.N), long(self.E)))
        return self.PublicRSAKey
    
    def toMixFormat(self):
        encodedData = struct.pack('<H', 1024)
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(self.N), 128, 0))
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(self.E), 128, 0))
        
        sanitycheck = hashlib.md5(encodedData[2:258]).hexdigest()
        encodedData = b64encode(encodedData)
        
        if sanitycheck != self.KeyId:
            raise Exception("Sanitycheck failed on exporting a Public Key to Mix Format")
        
        str = ""
        str += "-----Begin Mix Key-----\n"
        str += self.KeyId + "\n"
        str += "258\n"
        str += splitToNPerLine(encodedData) + "\n"
        str += "-----End Mix Key-----\n"
        return str
    def getMixKeyHeader(self):
        str = self.ShortName + " " + self.Address + " " + self.KeyId + " " + self.Version + " "
        str += "M" if self.Middleman else ""
        str += "C" if self.Compress else ""
        str += self.News
        return str
    def pprint(self):
        print "Shortname:", self.ShortName
        print "Address  :", self.Address
        print "Version  :", self.Version
        print "Protocol :", self.Protocol
        print "Middleman:", self.Middleman
        print "Compress :", self.Compress
        print "News     :", self.News
        print "Key ID   :", self.KeyId
        print "Key Len  :", self.KeyLen
        print "Key Val  :" #, keyval
        print "    Len  :", self.Decoded_KeyLen
        print "      N  :", self.N
        print "      E  :", self.E
        print self.toMixFormat()
        
class PrivateMixKey:
    class State:
        NoState = 0
        Header = 1
        Created = 2 
        Expires = 3
        KeyID = 4
        Zero = 5
        IV = 6
        Key = 7
        Footer = 8
        Done = 9
    Created = 0
    Expires = 0
    KeyId = 0
    Zero = 0
    IV = 0
    KeyVal = ""
    Passphrase = ""
    
    IV_Decoded = ""
    KeyVal_Decoded = ""
    KeyVal_Decrypted = ""
    
    N = 0
    E = 0
    D = 0
    P = 0
    Q = 0
    DMP1 = 0
    DMQ1 = 0
    IQMP = 0
    def __init__(self, lines=None, passphrase=None):
        state = self.State.Header

        self.ShortName = ""
        self.Address = ""
        self.Protocol = ""
        self.Version = ""
        self.Middleman = ""
        self.Compress = ""
        self.News = ""
        self.Passphrase = passphrase
        
        if not lines: return
        
        for l in lines:
            l = l.strip()
            
            if not l: 
                continue
            elif l == "-----Begin Mix Key-----":
                if state != self.State.Header:
                    raise Exception("Found Header when wasn't expecting it")
                else:
                    state = self.State.Created
            elif state == self.State.Created:
                self.Created = l
                state = self.State.Expires
            elif state == self.State.Expires:
                self.Expires = l
                state = self.State.KeyID
            elif state == self.State.KeyID:
                self.KeyId = l
                state = self.State.Zero
            elif state == self.State.Zero:
                self.Zero = l
                state = self.State.IV
            elif state == self.State.IV:
                self.IV = l
                state = self.State.Key
            elif l == "-----End Mix Key-----":
                if state != self.State.Key:
                    raise Exception("Found Footer when wasn't expecting it")
                else:
                    state = self.State.Done
            elif state == self.State.Key:
                self.KeyVal += l
            else:
                raise Exception("Got Non-Blank Line that doesn't fit.")
        self.decode()
    @staticmethod
    def generate(passphrase):
        import Crypto.Random
        
        k = PrivateMixKey()
        k.Passphrase = passphrase
        k.Decoded_KeyLen = 712
        k.Created = "Created: " + time.strftime("%Y-%m-%d", time.gmtime(time.time()))
        k.Expires = "Expires: " + time.strftime("%Y-%m-%d", time.gmtime(time.time() + (365*24*60*60)))
        
        k.IV_Decoded = Crypto.Random.get_random_bytes(8)
        k.IV = b64encode(k.IV_Decoded)

        pyk = RSA.generate(1024)
        k.N = pyk.n
        k.E = pyk.e
        k.D = pyk.d
        k.P = pyk.p if pyk.p > pyk.q else pyk.q
        k.Q = pyk.q if pyk.p > pyk.q else pyk.p
        k.DMP1 = modinv(k.E, k.P-1)
        k.DMQ1 = modinv(k.E, k.Q-1)
        k.IQMP = modinv(k.Q, k.P)
        
        encodedData = struct.pack('<H', 1024)
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(k.N), 128, 0))
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(k.E), 128, 0))
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(k.D), 128, 0))
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(k.P), 64, 0))
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(k.Q), 64, 0))
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(k.DMP1), 64, 0))
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(k.DMQ1), 64, 0))
        encodedData += byteArrayToBinary(arrayLeftPad(bigEndian(k.IQMP), 64, 0))
        encodedData += byteArrayToBinary([0,0,0,0,0,0]) # Pad to 712
        
        k.KeyVal_Decrypted = encodedData
        k.KeyId = hashlib.md5(encodedData[2:258]).hexdigest()
        
        passhash = hashlib.md5(k.Passphrase).digest()
        des = DES3.new(passhash, DES3.MODE_CBC, IV=k.IV_Decoded)
        k.KeyVal_Decoded = des.encrypt(k.KeyVal_Decrypted)
        k.KeyVal = b64encode(k.KeyVal_Decoded)
        
        output = ""
        output += "-----Begin Mix Key-----\n"
        output += k.Created + "\n"
        output += k.Expires + "\n"
        output += k.KeyId + "\n"
        output += "0\n"
        output += k.IV + "\n"
        output += splitToNPerLine(k.KeyVal) + "\n"
        output += "-----End Mix Key-----\n"
        return output
    def decode(self):
        if not self.Passphrase:
            logging.debug("Will not be able to decrypt secret key w/o passphrase, supply as only argument")
            return
        logging.debug("Decrypting with passphrase")
    
        self.IV_Decoded = b64decode(self.IV)
        self.KeyVal_Decoded = b64decode(self.KeyVal)
        
        hash = hashlib.md5(self.Passphrase).digest()
        des = DES3.new(hash, DES3.MODE_CBC, IV=self.IV_Decoded)
        self.KeyVal_Decrypted = des.decrypt(self.KeyVal_Decoded)
        
        sanitycheck = hashlib.md5(self.KeyVal_Decrypted[2:258]).hexdigest()
        
        if len(self.KeyVal_Decrypted) != 712:
            raise Exception("Length is non-standard")
        elif sanitycheck != self.KeyId:
            raise Exception("Did not decrypt Key to it's Matching ID: " + sanitycheck + " != " + self.KeyId)
        else:
            logging.debug("Decrypted successfully, Key IDs match...")
        
        bytes128 = 'B' * 128
        bytes64  = 'B' * 64
        
        self.Decoded_KeyLen = struct.unpack('<H', self.KeyVal_Decrypted[0:2])[0]        #Unsigned Short, Little Endian
        self.N = bigEndian(struct.unpack('>' + bytes128, self.KeyVal_Decrypted[2:130]))   #128 Bytes
        self.E = bigEndian(struct.unpack('>' + bytes128, self.KeyVal_Decrypted[130:258])) #128 Bytes
        self.D = bigEndian(struct.unpack('>' + bytes128, self.KeyVal_Decrypted[258:386])) #128 Bytes
        self.P = bigEndian(struct.unpack('>' + bytes64, self.KeyVal_Decrypted[386:450])) #64 Bytes
        self.Q = bigEndian(struct.unpack('>' + bytes64, self.KeyVal_Decrypted[450:514])) #64 Bytes
        self.DMP1 = bigEndian(struct.unpack('>' + bytes64, self.KeyVal_Decrypted[514:578])) #64 Bytes
        self.DMQ1 = bigEndian(struct.unpack('>' + bytes64, self.KeyVal_Decrypted[578:642])) #64 Bytes
        self.IQMP = bigEndian(struct.unpack('>' + bytes64, self.KeyVal_Decrypted[642:706])) #64 Bytes
        
        if self.N - (self.P * self.Q) != 0:
            raise Exception("N - (P * Q) != 0")
        
        if self.P < self.Q:
            raise Exception("P < Q")
        phi = (self.P-1) * (self.Q-1)
        myd = modinv(self.E, phi)
        if myd != self.D:
            raise Exception("Did not calculate D to be the value given in the private key file.")
        mydmp1 = modinv(self.E, self.P-1)
        if mydmp1 != self.DMP1:
            raise Exception("Did not calculate DMP1 to be the value given in the private key file.")
        mydmq1 = modinv(self.E, self.Q-1)
        if mydmq1 != self.DMQ1:
            raise Exception("Did not calculate DMQ1 to be the value given in the private key file.")
        myiqmp = modinv(self.Q, self.P)
        if myiqmp != self.IQMP:
            raise Exception("Did not calculate IQMP to be the value given in the private key file.")
    def getPublicMixKey(self):
        key = PublicMixKey()
        key.N = self.N
        key.E = self.E
        key.KeyId = self.KeyId
        key.ShortName = self.ShortName
        key.Address = self.Address
        key.Protocol = self.Protocol
        key.Version = self.Version
        key.Middleman = self.Middleman
        key.Compress = self.Compress
        key.News = self.News
        return key
    
    PrivateRSAKey = None
    def getPCPrivateKey(self):
        if not self.PrivateRSAKey:
            self.PrivateRSAKey = RSA.construct((long(self.N), long(self.E), long(self.D), long(self.P), long(self.Q)))
        return self.PrivateRSAKey
    
    PublicRSAKey = None
    def getPCPublicKey(self):
        if not self.PublicRSAKey:
            self.PublicRSAKey = RSA.construct((long(self.N), long(self.E)))
        return self.PublicRSAKey

    def pprint(self):
        print " Created:", self.Created
        print " Expires:", self.Expires
        print "  Key ID:", self.KeyId

        if not self.Passphrase:
            print " Could not decrypt secret key"
        else:
            print "Shortname:", self.ShortName
            print "Address  :", self.Address
            print "Version  :", self.Version
            print "Protocol :", self.Protocol
            print "Middleman:", self.Middleman
            print "Compress :", self.Compress
            print "News     :", self.News
            print "Key Val  :" #, keyval
            print "    Len  :", self.Decoded_KeyLen
            print "      N  :", self.N
            print "      E  :", self.E
            print "      D  :", self.D
            print "      P  :", self.P
            print "      Q  :", self.Q
            print "   DMP1  :", self.DMP1
            print "   DMQ1  :", self.DMQ1
            print "   IQMP  :", self.IQMP
        print self.getPublicMixKey().toMixFormat()
   
    def loadPublicCapabilities(self, key):
        self.ShortName = key.ShortName
        self.Address = key.Address
        self.Protocol = key.Protocol
        self.Version = key.Version
        self.Middleman = key.Middleman
        self.Compress = key.Compress
        self.News = key.News
        
if __name__ == "__main__":
    logging.config.fileConfig("../../config/test_logging.conf")
    lines = sys.stdin.readlines()
    passphrase = ""
    if len(sys.argv) > 1:
        passphrase = sys.argv[1]
    
    k1 = parseMixKey(lines, passphrase)
    k1.pprint()
