#!/usr/bin/python

class MixPacketType:
    IntermediateHop = 0
    FinalHop = 1
    FinalHopPartialMessage = 2
    @staticmethod
    def toPretty(i):
        if i == MixPacketType.IntermediateHop: return "IntermediateHop"
        elif i == MixPacketType.FinalHop: return "FinalHop"
        elif i == MixPacketType.FinalHopPartialMessage: return "FinalHopPartialMessage"
        else: return "Hell if I know, strange value kid!"
