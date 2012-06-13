#!/usr/bin/python

import struct
import hashlib
from Crypto.Cipher import DES3, PKCS1_v1_5

from mixMath import *
from mixKeystore import *
from mixPacketType import *

class IntermediateMixHeader:
    def __init__(self, data, decryptionkey=None, decryptioniv=None):
        data = data[:512]
        
        des = DES3.new(decryptionkey, DES3.MODE_CBC, IV=decryptioniv)
        self.DecryptedData = des.decrypt(data)
        
        self.EncryptedToPublicKey = hexpad(bigEndian(binaryToByteArray(self.DecryptedData[0:16])), 32)

    def pprint(self):
        if getKeyStore().getPublicKey(self.EncryptedToPublicKey):
            print "\tIntermediate Header Packet"
            print "\t Encrypted To Public Key Id:", self.EncryptedToPublicKey
        else:
            print "\tIntermediate Header Packet (Encrypted To Unknown Key Id)"
            
class EncryptedMixHeader:
    PacketId = 0
    TDesKey = 0  #Used to Encrypted following Header Sections & Packet Body
    PacketTypeId = 0
    PacketInfo = 0
    Timestamp = 0
    Digest = 0
    def __init__(self, decryptedbinarydata):
        self.PacketId = bigEndian(binaryToByteArray(decryptedbinarydata[0:16]))
        self.TDesKey = decryptedbinarydata[16:40]
        self.PacketTypeId = binaryToByteArray(decryptedbinarydata[40])[0]
        
        byteIndex = 41
        if self.PacketTypeId == MixPacketType.IntermediateHop:
            self.IVs = []
            for i in range(19):
                self.IVs.append(decryptedbinarydata[byteIndex : byteIndex+8])
                byteIndex += 8
            
            self.RemailerAddress = decryptedbinarydata[byteIndex : byteIndex + 80].strip(chr(0)).strip()
            byteIndex += 80
            
        elif self.PacketTypeId == MixPacketType.FinalHop:
            self.MessageId = bigEndian(binaryToByteArray(decryptedbinarydata[byteIndex : byteIndex + 16]))
            byteIndex += 16
            
            self.IV = decryptedbinarydata[byteIndex : byteIndex + 8]
            byteIndex += 8
            
        elif self.PacketTypeId == MixPacketType.FinalHopPartialMessage:
            logging.warn("Entered PacketType.FinalHopPartialMessage - UNTESTED CODE")
            
            self.ChunkNumber = binaryToByteArray(decryptedbinarydata[byteIndex : byteIndex + 1])
            byteIndex += 1
            
            self.NumberOfChunks = binaryToByteArray(decryptedbinarydata[byteIndex : byteIndex + 1])
            byteIndex += 1
            
            self.MessageId = bigEndian(binaryToByteArray(decryptedbinarydata[byteIndex : byteIndex + 16]))
            byteIndex += 16
            
            self.IV = decryptedbinarydata[byteIndex : byteIndex + 8]
            byteIndex += 8
        else:
            raise Exception("Recieved unknown Packet Type Identifier:", self.PacketTypeId)
            
        self.Timestamp = mixTimestampFromBinary(decryptedbinarydata[byteIndex : byteIndex + 7])
        byteIndex += 7
        
        self.Digest = decryptedbinarydata[byteIndex : byteIndex + 16]
        
        sanitycheck = hashlib.md5(decryptedbinarydata[0:byteIndex]).digest()
        if sanitycheck != self.Digest:
            raise Exception("Did not hash encrypted mix header to its corresponding digest")
    def pprint(self):
        print "\t PacketId:  ", self.PacketId
        print "\t PacketType:", MixPacketType.toPretty(self.PacketTypeId), "(" + str(self.PacketTypeId) + ")"
        print "\t TDes Key:  ", hexpad(bigEndian(binaryToByteArray(self.TDesKey)), 24)
        print "\t Timestamp: ", self.Timestamp
        if self.PacketTypeId == MixPacketType.IntermediateHop:
            print "\t Remailer Address:", self.RemailerAddress
        elif self.PacketTypeId == MixPacketType.FinalHop:
            print "\t MessageId: ", self.MessageId
            print "\t IV:        ", hexpad(bigEndian(binaryToByteArray(self.IV)), 8)
        elif self.PacketTypeId == MixPacketType.FinalHopPartialMessage:
            print "\t Never seen a FinalHopPartialMessage before..."
    def getPayloadIV(self):
        if self.PacketTypeId == MixPacketType.IntermediateHop:
            return self.IVs[18]
        elif self.PacketTypeId == MixPacketType.FinalHop:
            return self.IV
        elif self.PacketTypeId == MixPacketType.FinalHopPartialMessage:
            raise Exception("Never seen a FinalHopPartialMessage before...")

class ParsedMixHeader:
    PublicKeyId = 0
    DataLength = 0
    TDESKey = 0  #Used only to decrypt the Encrypted Header Part, not used elsewhere
    IV = 0       #Used only to decrypt the Encrypted Header Part, not used elsewhere
    EncHeader = 0
    Padding = 0
    EncHeader_Decrypted = 0
    DecryptedHeader = ""
    def __init__(self, data):
        data = data[:512]
        
        self.PublicKeyId = hexpad(bigEndian(binaryToByteArray(data[0:16])), 32)
        self.DataLength = struct.unpack('B', data[16])[0]
        if self.DataLength != 128:
            raise Exception("Got an unexpected Data Length from the MixHeader:", self.DataLength)
        self.TDESKey = data[17:145]
        self.IV = data[145:153]
        self.EncHeader = data[153:481]
        self.Padding = data[481:512]
        
        self.TDESKey_Decrypted = 0
        
        ks = getKeyStore()
        privKey = ks.getPrivateKey(self.PublicKeyId)
        if not privKey:
            raise Exception("Could not decrypt MixHeader, Private Key for " + self.PublicKeyId + " not found in keystore: " + str(ks.listPrivateKeys()))
        
        rsa = PKCS1_v1_5.new(privKey.getPCPrivateKey())
        self.TDESKey_Decrypted = rsa.decrypt(self.TDESKey, "This is most certainly not the key")
        
        if self.TDESKey_Decrypted == "This is most certainly not the key":
            raise Exception("Could not decrypt MixHeader Encrypted Header")
        
        des = DES3.new(self.TDESKey_Decrypted, DES3.MODE_CBC, IV=self.IV)
        self.EncHeader_Decrypted = des.decrypt(self.EncHeader)

        self.DecryptedHeader = EncryptedMixHeader(self.EncHeader_Decrypted)
        
    def pprint(self):
        if self.DecryptedHeader:
            print "\tPacket Header ---------------------------"
            print "\t Public Key Id:", self.PublicKeyId
            self.DecryptedHeader.pprint()
        