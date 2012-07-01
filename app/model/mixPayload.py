#!/usr/bin/python

import struct
from Crypto.Cipher import DES3

from mixMath import *

class IntermediateMixPayload:
    def __init__(self, data, decryptionkey=None, decryptioniv=None):
        des = DES3.new(decryptionkey, DES3.MODE_CBC, IV=decryptioniv)
        self.DecryptedData = des.decrypt(data)
    def pprint(self):
        print "\tIntermediate Payload Packet"
        
class ParsedMixPayload:
    class UserDataType:
        Gzip = 1
        Email = 2
        Plain = 3
        Empty = 100
        @staticmethod
        def toPretty(i):
            if i == ParsedMixPayload.UserDataType.Gzip: return "Gzip"
            elif i == ParsedMixPayload.UserDataType.Email: return "Email"
            elif i == ParsedMixPayload.UserDataType.Plain: return "Plain"
            elif i == ParsedMixPayload.UserDataType.Empty: return "Empty"
            else: return "Hell if I know, strange value kid!"
    DecryptionKey = 0
    IV = 0
    DecryptedData = 0
    
    NumDestinationFields = 0
    DestinationFields = []
    NumHeaderFields = 0
    HeaderFields = []
    UserData = 0
    UserDataTypeId = 0
    def __init__(self, data, key, iv):
        self.DecryptionKey = key
        self.IV = iv
        des = DES3.new(self.DecryptionKey, DES3.MODE_CBC, IV=self.IV)
        self.DecryptedData = des.decrypt(data)
        
        self.DataLength = littleEndian(binaryToByteArray(self.DecryptedData[0:4]))
        byteIndex = 4
        
        self.DecryptedData = self.DecryptedData[0 : self.DataLength + 4]
        
        self.DestinationFields = []
        self.NumDestinationFields = struct.unpack('B', self.DecryptedData[byteIndex])[0]
        byteIndex += 1
        for i in range(self.NumDestinationFields):
            self.DestinationFields.append(self.DecryptedData[byteIndex : byteIndex + 80].strip(chr(0)).strip())
            byteIndex += 80
        
        self.HeaderFields = []
        self.NumHeaderFields = struct.unpack('B', self.DecryptedData[byteIndex])[0]
        byteIndex += 1
        for i in range(self.NumHeaderFields):
            self.HeaderFields.append(self.DecryptedData[byteIndex : byteIndex + 80].strip(chr(0)).strip())
            byteIndex += 80
            
        self.UserData = self.DecryptedData[byteIndex : ]
        self.UserDataTypeId = 0
        
        if self.UserData:
            if self.UserData[0] == 31 and self.UserData[1] == 139:
                self.UserDataTypeId = self.UserDataType.Gzip
                raise Exception("Got a gzipped payload - don't know how to handle this")
            elif self.UserData[0] == 35 and self.UserData[1] == 35 and self.UserData[2] == 13:
                self.UserDataTypeId = self.UserDataType.Email
                raise Exception("Got an email payload - don't know how to handle this")
            else:
                self.UserDataTypeId = self.UserDataType.Plain
                self.UserData = self.UserData
        else:
            self.UserDataTypeId = self.UserDataType.Empty
            self.UserData = ""
            
        # Quicksilver seems to send mail in a nonstandard fashion.  It writes 
        #  no Destination Fields, nor Header Fields.  Instead it places a ##
        #  aand then the headers, a blank line, and the body.  
        
        if self.UserData.strip().startswith("##"):
            PossibleQSMessage = self.UserData.strip()[3:]
            lines = PossibleQSMessage.split("\n")
            
            QSHeaders = []
            QSDestinations = []
            beginQSBody = 0
            for i in range(len(lines)):
                print ">", lines[i]
                if lines[i].strip():
                    h, sep, v = lines[i].partition(':')
                    if h and v:
                        if h.strip() == "To":
                            QSDestinations.append(lines[i])
                        else:
                            QSHeaders.append(lines[i])
                else:
                    beginQSBody = i
                    break
            
            self.HeaderFields = QSHeaders
            self.NumHeaderFields = len(QSHeaders)
            self.DestinationFields = QSDestinations
            self.NumDestinationFields = len(QSDestinations)
            self.UserData = "\n".join(lines[beginQSBody+1:])
        
    def pprint(self):
        print "\tPacket Body -----------------------------"
        print "\t Data Length       :", self.DataLength
        print "\t Destination Fields:", self.NumDestinationFields
        for d in self.DestinationFields:
            print "\t   ", d
        print "\t Header Fields     :", self.NumHeaderFields
        for h in self.HeaderFields:
            print "\t   ", h
        print "\t User Data Type    :", self.UserDataType.toPretty(self.UserDataTypeId), "(" + str(self.UserDataTypeId) + ")"
        print "\t User Data:"
        if self.UserDataTypeId == self.UserDataType.Plain:
            print "\t   ", self.UserData.replace("\n", "\n\t   ")
            
    def getHeader(self, searchfor):
        results = []
        for field in self.HeaderFields:
            h, sep, v = field.partition(':')
            if h.strip().lower() == searchfor.strip().lower():
                results.append(v.strip())
        return results