#!/usr/bin/python

class MixPacketType:
    IntermediateHop = 0
    FinalHop = 1
    FinalHopPartialMessage = 2
    DummyMessage = 1000
    @staticmethod
    def toPretty(i):
        if i == MixPacketType.IntermediateHop: return "IntermediateHop"
        elif i == MixPacketType.FinalHop: return "FinalHop"
        elif i == MixPacketType.FinalHopPartialMessage: return "FinalHopPartialMessage"
        elif i == MixPacketType.DummyMessage: return "DummyMessage"
        else: return "Hell if I know, strange value kid!"
