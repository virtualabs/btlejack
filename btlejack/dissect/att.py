"""
ATT Dissector/Assembler
"""
from struct import pack, unpack

UUIDS_ALIAS = {
    '1800': 'Generic Access',
    '1811': 'Alert Notification Service',
    '180f': 'Battery Service',
    '1805': 'Current Time Service',
    '1801': 'Generic Attribute',
    '1802': 'Immediate Alert',
    '1803': 'Link Loss',
    '1827': 'Mesh Provisionning Service',
    '1828': 'Mesh Proxy Service',
    '2a19': 'Battery Level',
    '2a00': 'Device Name',
    '2a01': 'Appearance'
}

class UUID(object):
    def __init__(self, uuid):
        if len(uuid) == 2:
            self.size = 2
            self.uuid = uuid
        else:
            self.size = 16
            self.uuid = uuid

    def to_bytes(self):
        return bytes(self.uuid)

    def __str__(self):
        return ''.join(['%02x' % c for c in self.to_bytes()[::-1]])

    @staticmethod
    def from_bytes(raw):
        if len(raw) == 2 or len(raw) == 16:
            return UUID(raw)
        else:
            return None

class PrimaryServicesUUID(UUID):
    def __init__(self):
        super().__init__([0x00, 0x28])

class GATTCharacteristicDeclaration(UUID):
    def __init__(self):
        super().__init__([0x03, 0x28])

class Attribute(object):
    def __init__(self, opcode=0x00, authsig=None, command=False):
        self.opcode = opcode
        self.authsig = authsig
        self.command = command
        self.parameters = None

    def is_command(self):
        return self.command

    def get_method(self):
        return self.opcode

class ErrorResponse(Attribute):
    """
    Error response Attribute
    """
    def __init__(self, req_op_code=0, attr_handle=0, code=0):
        super().__init__(opcode=0x01)
        self.req_op_code = req_op_code
        self.attr_handle = attr_handle
        self.code = code

    def to_bytes(self):
        raw = bytes([self.opcode]) + pack(
            '<BHB',
            self.req_op_code,
            self.attr_handle,
            self.code
        )
        return raw

    @staticmethod
    def from_bytes(raw):
        req_op_code, attr_handle, code = unpack('<BHB', raw[1:])
        return ErrorResponse(
            req_op_code,
            attr_handle,
            code
        )

class ExchangeMtuRequest(Attribute):
    def __init__(self, mtu=23):
        super().__init__(opcode=0x2)
        self.mtu = mtu

    def to_bytes(self):
        return bytes([self.opcode]) + pack('<H', self.mtu)

    @staticmethod
    def from_bytes(raw):
        mtu = unpack('<H', raw[1:])[0]
        return ExchangeMtuRequest(mtu)

class ExchangeMtuResponse(Attribute):
    def __init__(self, mtu=23):
        super().__init__(opcode=0x3)
        self.mtu = mtu

    def to_bytes(self):
        return bytes([self.opcode]) + pack('<H', self.mtu)

    @staticmethod
    def from_bytes(raw):
        mtu = unpack('<H', raw[1:])[0]
        return ExchangeMtuResponse(mtu)

class ReadByTypeRequest(Attribute):
    def __init__(self, start=0, end=0, type_uuid=None):
        super().__init__(opcode=0x08)
        self.start = start
        self.end = end
        self.type = type_uuid

    def to_bytes(self):
        raw = bytes([self.opcode]) + pack('<HH', self.start, self.end)
        raw += self.type.to_bytes()
        return raw

    @staticmethod
    def from_bytes(raw):
        start, end = unpack('<HH', raw[1:5])
        attr_type = UUID(raw[5:])
        return ReadByTypeRequest(start, end, attr_type)

class ReadByTypeResponse(Attribute):
    def __init__(self, datas, length):
        super().__init__(opcode=0x09)
        self.attr_datas = datas
        self.length = length

    def to_bytes(self):
        raw = bytes([self.opcode, self.length])
        for i in self.attr_datas:
            raw += i.to_bytes()
        return raw

    @staticmethod
    def from_bytes(raw):
        length = raw[1]
        datas = []
        for i in range(int((len(raw) - 2)/length)):
            datas.append(raw[2+i*length:2+(i+1)*length])
        return ReadByTypeResponse(datas, length)


class ReadByGroupTypeRequest(Attribute):
    def __init__(self, start=0, end=0, type_uuid=None):
        super().__init__(opcode=0x10)
        self.start = start
        self.end = end
        self.type = type_uuid

    def to_bytes(self):
        raw = bytes([self.opcode]) + pack('<HH', self.start, self.end)
        raw += self.type.to_bytes()
        return raw

    @staticmethod
    def from_bytes(raw):
        start, end = unpack('<HH', raw[1:5])
        attr_type = UUID(raw[5:])
        return ReadByGroupTypeRequest(start, end, attr_type)

class ReadByGroupTypeResponse(Attribute):
    def __init__(self, datas, length):
        super().__init__(opcode=0x11)
        self.attr_datas = datas
        self.length = length

    def to_bytes(self):
        raw = bytes([self.opcode, self.length])
        for i in self.attr_datas:
            raw += i.to_bytes()
        return raw

    @staticmethod
    def from_bytes(raw):
        length = raw[1]
        datas = []
        for i in range(int((len(raw) - 2)/length)):
            datas.append(raw[2+i*length:2+(i+1)*length])
        return ReadByGroupTypeResponse(datas, length)

class WriteRequest(Attribute):
    def __init__(self, handle, value):
        super().__init__(opcode=0x12)
        self.handle = handle
        self.value = value

    def to_bytes(self):
        raw = bytes([self.opcode]) + pack('<H', self.handle) + self.value
        return raw

    @staticmethod
    def from_bytes(raw):
        handle = unpack('<H', raw[1:])[0]
        value = raw[3:]
        return WriteRequest(handle, value)

class WriteCommand(Attribute):
    def __init__(self, handle, value):
        super().__init__(opcode=0x52)
        self.handle = handle
        self.value = value

    def to_bytes(self):
        raw = bytes([self.opcode]) + pack('<H', self.handle) + self.value
        return raw

    @staticmethod
    def from_bytes(raw):
        handle = unpack('<H', raw[1:3])[0]
        value = raw[3:]
        return WriteRequest(handle, value)


class WriteResponse(Attribute):
    def __init__(self):
        super().__init__(opcode=0x13)

    def to_bytes(self):
        return bytes([self.opcode])

    @staticmethod
    def from_bytes(raw):
        return WriteResponse()

class ReadRequest(Attribute):
    def __init__(self, handle):
        super().__init__(opcode=0x0a)
        self.handle = handle

    def to_bytes(self):
        return bytes([self.opcode]) + pack('<H', self.handle)

    @staticmethod
    def from_bytes(raw):
        handle = unpack('<H', raw[1:3])
        return ReadRequest(handle)

class ReadResponse(Attribute):
    def __init__(self, value):
        super().__init__(opcode=0x0b)
        self.value = value

    def to_bytes(self):
        return bytes([self.opcode]) + self.value

    @staticmethod
    def from_bytes(raw):
        return ReadResponse(raw[1:])

class ATT(object):
    """
    ATT protocol class
    """

    ATTRIBUTES = {
        0x01: ErrorResponse,
        0x02: ExchangeMtuRequest,
        0x03: ExchangeMtuResponse,
        0x08: ReadByTypeRequest,
        0x09: ReadByTypeResponse,
        0x0A: ReadRequest,
        0x0B: ReadResponse,
        0x10: ReadByGroupTypeRequest,
        0x11: ReadByGroupTypeResponse,
        0x12: WriteRequest,
        0x13: WriteResponse,
        0x52: WriteCommand,

        """
        0x04: FindInfoRequest,
        0x05: FindInfoResponse,
        0x06: FindByTypeValueRequest,
        0x07: FindByTypeValueResponse,
        0x08: ReadByTypeRequest,
        0x09: ReadByTypeResponse,
        0x0A: ReadRequest,
        0x0B: ReadResponse,
        0x0C: ReadBlobRequest,
        0x0D: ReadBlobResponse,
        0x0E: ReadMultipleRequest,
        0x0F: ReadMultipleResponse,
        0x10: ReadByGroupTypeRequest,
        0x11: ReadByGroupTypeResponse,
        0x12: WriteRequest,
        0x13: WriteResponse,
        0x52: WriteCommand,
        0xD2: SignedWriteCommand,
        0x16: PrepareWriteRequest,
        0x17: PrepareWriteResponse,
        0x18: ExecuteWriteRequest,
        0x19: ExecuteWriteResponse,
        0x1B: HandleValueNotification,
        0x1D: HandleValueIndication,
        0x1E: HandleValueConfirmation
        """:''
    }

    def __init__(self, attribute):
        """
        Assembler.
        """
        self.method = attribute.get_method()
        self.command = attribute.is_command()
        self.authsig = attribute.authsig
        self.payload = attribute

    def to_bytes(self):
        """
        Serialize
        """
        att_opcode = 0x00
        if self.authsig is not None:
            att_opcode |= (1 << 7)
        if self.command:
            att_opcode |= (1 << 6)
        att_opcode |= (self.method & 0x1F)
        if self.authsig is not None:
            return self.payload.to_bytes() + self.authsig
        else:
            return self.payload.to_bytes()

    @staticmethod
    def from_bytes(raw):
        method = raw[0]
        if method in ATT.ATTRIBUTES:
            return ATT(
                ATT.ATTRIBUTES[method].from_bytes(
                    raw
                )
            )
        else:
            return None
