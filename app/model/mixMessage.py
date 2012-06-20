#!/usr/bin/python

import sys, struct, random
import hashlib
from base64 import *

import logging, logging.config

from mixMath import *
from mixConfig import *
from mixKeystore import *
from mixPacketType import *
from mixHeader import *
from mixPayload import *


class MixMessage:
    class State:
        Colons = 1
        Type = 2
        Header = 3
        Length = 4
        Digest = 5
        Packet = 6
        Footer = 7
        Done = 8
    Type = 0
    Length = 0
    Digest = 0
    Packet = ""
    PacketType = 0
    def __init__(self, lines):
        if isinstance(lines, str) or isinstance(lines, unicode):
            lines = lines.split("\n")

        state = self.State.Colons
        for l in lines:
           l = l.strip()
           
           if not l: continue
           elif l == "::":
               if state != self.State.Colons:
                   raise Exception("Found Colons when wasn't expecting it")
               else:
                   state = self.State.Type
           elif state == self.State.Type:
               self.Type = l
               state = self.State.Header
           elif l == "-----BEGIN REMAILER MESSAGE-----":
               if state != self.State.Header:
                   raise Exception("Found Header when wasn't expecting it")
               else:
                   state = self.State.Length
           elif state == self.State.Length:
               self.Length = l
               state = self.State.Digest
           elif state == self.State.Digest:
               self.Digest = l
               state = self.State.Packet
           elif l == "-----END REMAILER MESSAGE-----":
               if state != self.State.Packet:
                   raise Exception("Found Footer when wasn't expecting it")
               else:
                   state = self.State.Done
           elif state == self.State.Packet:
               self.Packet += l
           else:
               raise Exception("Got Non-Blank Line that doesn't fit at state", state, l)
                   
        self.decode()
    def decode(self):
        self.Packet_Decoded = b64decode(self.Packet)
        if len(self.Packet_Decoded) != 20480:
            raise Exception("Length is non-standard:", len(self.Packet_Decoded))
        self.Digest_Decoded = b64decode(self.Digest)
            
        sanitycheck = hashlib.md5(self.Packet_Decoded).digest()
        if sanitycheck != self.Digest_Decoded:
            raise Exception("Did not hash message to it's Matching ID")
        
        self.Headers= []
        for i in range(20):
            h = None
            if i == 0:
                h = ParsedMixHeader(self.Packet_Decoded[(512 * i) : (512 * (i+1))])
            
            elif self.Headers[0].DecryptedHeader.PacketTypeId == MixPacketType.IntermediateHop:
                h = IntermediateMixHeader(self.Packet_Decoded[(512 * i) : (512 * (i+1))], self.Headers[0].DecryptedHeader.TDesKey, self.Headers[0].DecryptedHeader.IVs[i-1])
            
            if h: self.Headers.append(h)
        
        if self.Headers[0].DecryptedHeader.PacketTypeId == MixPacketType.FinalHop:
            self.Payload = ParsedMixPayload(self.Packet_Decoded[512*20:], self.Headers[0].DecryptedHeader.TDesKey, self.Headers[0].DecryptedHeader.getPayloadIV())
        elif self.Headers[0].DecryptedHeader.PacketTypeId == MixPacketType.IntermediateHop:
            self.Payload = IntermediateMixPayload(self.Packet_Decoded[512*20:], self.Headers[0].DecryptedHeader.TDesKey, self.Headers[0].DecryptedHeader.getPayloadIV())
            
        if isinstance(self.Payload, ParsedMixPayload) and "null:" in self.Payload.DestinationFields:
            self.PacketType = MixPacketType.DummyMessage
        else:
            self.PacketType = self.Headers[0].DecryptedHeader.PacketTypeId
        
        
    def pprint(self):
        print "Sender Type: ", self.Type
        print "Msg Len:     ", self.Length
        print "Msg Headers:"
        for h in self.Headers:
            h.pprint()
        self.Payload.pprint()

    def _buildNextHopMessage(self):
        if self.PacketType != MixPacketType.IntermediateHop:
            raise Exception("Called buildNextHopMessage when this is not an Intermediate Hope")

        messagedata = ""
        for h in self.Headers[1:]:
            if len(h.DecryptedData) != 512:
                raise Exception("Header Data is not 512 bytes")
            messagedata += h.DecryptedData
        
        #Append a final, random, 512 byte header
        for i in range(512): messagedata += chr(random.randrange(256))
        
        messagedata += self.Payload.DecryptedData
            
        output = "::" + "\n"
        output += "Remailer-Type: " + getRemailerConfig('remailerversion')  + "\n"
        output += "\n"
        output += "-----BEGIN REMAILER MESSAGE-----" + "\n"
        output += "20480" + "\n"
        output += b64encode(hashlib.md5(messagedata).digest()) + "\n"
        messagedata = b64encode(messagedata)
        output += splitToNPerLine(messagedata) + "\n"
        output += "-----END REMAILER MESSAGE-----" + "\n"
        
        return output
    def deliveryTo(self):
        if self.PacketType == MixPacketType.IntermediateHop:
            return self.Headers[0].DecryptedHeader.RemailerAddress
        elif self.PacketType == MixPacketType.FinalHop:
            return self.Payload.DestinationFields
        elif self.PacketType == MixPacketType.DummyMessage:
            return Exception("Called deliveryTo on a Dummy Message")
        else:
            raise Exception("Called deliveryTo with a PacketType that is unhandled")
    def deliverySubject(self):
        if self.PacketType == MixPacketType.IntermediateHop:
            return ""#Subject doesn't matter
        elif self.PacketType == MixPacketType.FinalHop:
            return ' / '.join(self.Payload.getHeader('Subject'))
        elif self.PacketType == MixPacketType.DummyMessage:
            return Exception("Called deliverySubject on a Dummy Message")
        else:
            raise Exception("Called deliverySubject with a PacketType that is unhandled")
    def deliveryBody(self):
        if self.PacketType == MixPacketType.IntermediateHop:
            return self._buildNextHopMessage()
        elif self.PacketType == MixPacketType.FinalHop:
            return self.Payload.UserData
        elif self.PacketType == MixPacketType.DummyMessage:
            return Exception("Called deliveryBody on a Dummy Message")
        else:
            raise Exception("Called deliveryBody with a PacketType that is unhandled")
    def deliveryHeaders(self):
        if self.PacketType == MixPacketType.IntermediateHop:
            return []
        elif self.PacketType == MixPacketType.FinalHop:
            results = []
            for field in self.Payload.HeaderFields:
                h, sep, v = field.partition(':')
                h = h.strip()
                v = v.strip()
                if getRemailerConfig().allowHeader(h, v):
                    results.append((h, v))
            return results
        elif self.PacketType == MixPacketType.DummyMessage:
            return Exception("Called deliveryHeaders on a Dummy Message")
        else:
            raise Exception("Called deliveryHeaders with a PacketType that is unhandled")
            
   
if __name__ == "__main__":
    logging.config.fileConfig("../../config/test_logging.conf")
    
    if len(sys.argv) > 1:
        extrakeyfile = sys.argv[1]
        extrakeypassphrase = sys.argv[2]
        f = open(extrakeyfile, "r")
        extrakeylines = f.readlines()
        f.close()
        getKeyStore().addKey(extrakeylines, extrakeypassphrase)
    
    lines = sys.stdin.readlines()
    msg = MixMessage(lines)
    msg.pprint()
    print "========================"
    if msg.PacketType == MixPacketType.DummyMessage:
        print "Dummy Message"
    else:
        print msg.deliveryTo()
        print msg.deliverySubject()
        print msg.deliveryHeaders()
        print msg.deliveryBody()