"""
L2CAP Dissector/Assembler
"""
from struct import pack, unpack
from .att import ATT

class L2CAPException(Exception):
    def __init__(self):
        super().__init__()

class L2CAP(object):
    """
    L2CAP management class.
    """

    ATT_PROTO = 0x4

    def __init__(self, payload):
        self.payload = payload

    def to_bytes(self):
        raw_payload = self.payload.to_bytes()
        return pack('<HH', len(raw_payload), self.ATT_PROTO) + raw_payload

    @staticmethod
    def from_bytes(raw):
        """
        Dissect L2CAP message from bytes
        """
        raw_length, proto = unpack('<HH', raw[:4])
        if proto==L2CAP.ATT_PROTO:
            # parse content with ATT dissector
            return L2CAP(ATT.from_bytes(raw[4:4 + raw_length]))
        else:
            raise L2CAPException()
