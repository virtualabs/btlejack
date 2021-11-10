"""
Packets module

This module provides the `PacketRegistry` packet decoder, along with all the
required packet classes.
"""

from struct import pack, unpack

class register_packet(object):
    """
    Decorator used to register packet classes with the corresponding operations
    and types.
    """
    def __init__(self, packet_op, packet_type):
        self.packet_op = packet_op
        self.packet_type = packet_type


    def __call__(self, clazz):
        """
        Register our class along with the corresponding packet operation and
        type.
        """
        PacketRegistry.register(
            self.packet_op,
            self.packet_type,
            clazz
        )
        return clazz

class PacketRegistry(object):
    """
    Packet registry.

    This class acts as a registry and provide a static method to decode raw
    packets into the corresponding classes.
    """

    registry = {}

    @staticmethod
    def register(packet_op, packet_type, packet_class):
        """
        Associate a packet class with its characteristics.
        """
        pkt_characs = packet_op | ((packet_type&0x0f) << 4)
        if pkt_characs not in PacketRegistry.registry:
            PacketRegistry.registry[pkt_characs] = packet_class

    @staticmethod
    def decode(packet):
        """
        Decode packet into corresponding class instance.
        """
        pkt_characs = packet.operation | ((packet.flags&0x0F) << 4)
        if pkt_characs in PacketRegistry.registry:
            return PacketRegistry.registry[pkt_characs].from_raw(packet)
        else:
            return packet


class Packet(object):
    """
    Serial packet representation.
    """

    OP_VERSION = 0x01
    OP_RESET = 0x02
    OP_SCAN_AA = 0x03
    OP_RECOVER = 0x04

    OP_RECOVER_AA = 0x04
    OP_RECOVER_AA_CHM = 0x05
    OP_RECOVER_AA_CHM_HOPINTER = 0x06

    OP_SNIFF_CONREQ = 0x07
    OP_ENABLE_JAMMING = 0x08
    OP_ENABLE_HIJACKING = 0x09
    OP_SEND_PKT = 0x0A
    OP_CCHM = 0x0B
    OP_DEBUG = 0x0E
    OP_VERBOSE = 0x0F

    F_CMD = 0x01
    F_RESP = 0x02
    F_NOTIFICATION = 0x04

    N_ACCESS_ADDRESS = 0x00
    N_CRC = 0x01
    N_CHANNEL_MAP = 0x02
    N_HOP_INTERVAL = 0x03
    N_HOP_INCREMENT = 0x04
    N_PACKET = 0x05
    N_CONN_REQ = 0x06
    N_PACKET_NORDIC = 0x07
    N_HIJACK_STATUS = 0x08
    N_CONN_LOST = 0x09
    N_CSA2_PRNG = 0x0A

    def __init__(self, operation, data, flags):
        """
        Constructor
        """
        self.operation = operation
        self.data = data
        self.flags = flags

    @staticmethod
    def crc(data, previous=0xff):
        """
        Compute 8-bit CRC
        """
        c = previous
        for i in list(data):
            c ^= i
        return c

    @staticmethod
    def fromBytes(data):
        """
        Extract packet from bytes.
        """
        # check magic
        if data[0] != 0xbc:
            return None

        # check crc
        _crc = Packet.crc(data[:-1])
        if _crc == data[-1]:
            # parse operation and flags
            op = data[1] & 0x0F
            flags = (data[1]>>4)&0x0F

            # get packet size
            pkt_size = unpack('<H', data[2:4])[0]

            # check size
            if pkt_size == len(data) - 5:
                return Packet(op, data[4:4+pkt_size], flags)
            else:
                return None
        else:
            return None

    def toBytes(self):
        """
        Serialize packet to bytes
        """
        # generate header
        length_l = len(self.data) & 0xFF
        length_h = (len(self.data)>>8) & 0xFF
        buffer = [
            0xBC,
            (self.operation & 0x0F) | ((self.flags&0x0F) << 4),
            length_l,
            length_h
        ]
        for i in self.data:
            buffer.append(i)
        _crc = Packet.crc(buffer)
        buffer.append(_crc)
        return bytes(buffer)

    def __str__(self):
        """
        String representation.
        """
        hex_payload = ' '.join(['%02x' % c for c in self.data])
        return "<Packet op=%02x flags=%02x data='%s'>" % (
            self.operation,
            self.flags,
            #self.data
            hex_payload
        )

    def __repr__(self):
        """
        Representation string
        """
        return str(self)


###################################
# Commands and responses
###################################


@register_packet(Packet.OP_DEBUG, Packet.F_RESP)
class DebugPacket(Packet):
    """
    Debug message packet
    """

    def __init__(self, message):
        """
        Constructor.
        """
        self.message = message
        super().__init__(Packet.OP_DEBUG, message, Packet.F_RESP)

    def __repr__(self):
        return '<pkt> DEBUG: %s' % self.message

    @staticmethod
    def from_raw(packet):
        """
        Decode a raw packet.
        """
        return DebugPacket(packet.data)

@register_packet(Packet.OP_VERBOSE, Packet.F_RESP)
class VerbosePacket(Packet):
    """
    Debug message packet
    """

    def __init__(self, message):
        """
        Constructor.
        """
        self.message = message
        super().__init__(Packet.OP_VERBOSE, message, Packet.F_RESP)

    def __repr__(self):
        return '<pkt> VERBOSE: %s' % self.message

    @staticmethod
    def from_raw(packet):
        """
        Decode a raw packet.
        """
        return VerbosePacket(packet.data)


class ResetCommand(Packet):
    """
    Reset command.
    """
    def __init__(self):
        super().__init__(Packet.OP_RESET, bytes([]), Packet.F_CMD)

@register_packet(Packet.OP_RESET, Packet.F_RESP | Packet.F_CMD)
class ResetResponse(Packet):
    """
    Reset response packet.
    """
    def __init__(self):
        super().__init__(Packet.OP_RESET, bytes([]), Packet.F_RESP)


    def __str__(self):
        """
        String conversion.
        """
        return '<pkt> Reset response'

    def __repr__(self):
        return str(self)

    @staticmethod
    def from_raw(packet):
        return ResetResponse()


class VersionCommand(Packet):
    """
    Version command.
    """
    def __init__(self):
        super().__init__(Packet.OP_VERSION, bytes([]), Packet.F_CMD)

@register_packet(Packet.OP_VERSION, Packet.F_RESP)
class VersionResponse(Packet):
    """
    Version response.
    """
    def __init__(self, major=0, minor=0):
        self.major, self.minor = major, minor
        super().__init__(Packet.OP_VERSION, bytes([major, minor]), Packet.F_CMD | Packet.F_RESP)

    def __str__(self):
        return '<pkt> Version: %d %d' % (self.major, self.minor)

    def __repr__(self):
        return str(self)


    @staticmethod
    def from_raw(packet):
        """
        Parse major and minor versions.
        """
        return VersionResponse(packet.data[0],packet.data[1])


class ScanConnectionsCommand(Packet):
    """
    Version command.
    """
    def __init__(self):
        super().__init__(Packet.OP_SCAN_AA, bytes([]), Packet.F_CMD)

@register_packet(Packet.OP_SCAN_AA, Packet.F_CMD | Packet.F_RESP)
class ScanConnectionsResponse(Packet):
    """
    Scan connection response.
    """
    def __init__(self):
        super().__init__(Packet.OP_SCAN_AA, bytes([]), Packet.F_CMD)

    def __str__(self):
        return '<pkt> ScanConnectionsResponse'

    @staticmethod
    def from_raw(packet):
        """
        Convert raw packet into ScanConnectionsResponse.
        """
        return ScanConnectionsResponse()

class CollabChannelMapCommand(Packet):
    """
    Collaborative channel map command
    """
    def __init__(self, access_address, crcinit, start=0, stop=37):
        params = pack('<IBBBBB',
            access_address,
            crcinit & 0xff,
            (crcinit & 0xff00) >> 8,
            (crcinit & 0xff0000) >> 16,
            start,
            stop
        )
        print(len(params))
        super().__init__(Packet.OP_CCHM, params, Packet.F_CMD)

@register_packet(Packet.OP_CCHM, Packet.F_CMD | Packet.F_RESP)
class CollabChannelMapResponse(Packet):
    def __init__(self):
        super().__init__(Packet.OP_CCHM, bytes([]), Packet.F_CMD | Packet.F_RESP)

    def __str__(self):
        return '<pkt> CollabChannelMapResponse'

    @staticmethod
    def from_raw(packet):
        """
        Convert raw packet into CollabChannelMapResponse.
        """
        return CollabChannelMapResponse()


@register_packet(Packet.N_ACCESS_ADDRESS, Packet.F_NOTIFICATION)
class AccessAddressNotification(Packet):
    """
    Access Address notification sent while discovering existing
    AA.
    """
    def __init__(self, channel=0, rssi=0, access_address=None):
        """
        Constructor.
        """
        self.channel = channel
        self.rssi = rssi
        self.access_address = access_address
        payload = pack('<BBI', self.channel, self.rssi, self.access_address)
        super().__init__(
            Packet.N_ACCESS_ADDRESS,
            bytes(payload),
            Packet.F_NOTIFICATION
        )

    def __str__(self):
        return "<AccessAddressNotification channel='%d' rssi='%s' address='%02x:%02x:%02x:%02x'>" % (
            self.channel,
            str(-self.rssi),
            (self.access_address & 0xff000000) >> 24,
            (self.access_address & 0xff0000) >> 16,
            (self.access_address & 0xff00) >> 8,
            self.access_address & 0xff,

        )

    @staticmethod
    def from_raw(packet):
        """
        Convert raw packet to AccessAddressNotification.
        """
        channel = packet.data[0]
        rssi = packet.data[1]
        access_address = unpack('<I', packet.data[2:6])[0]
        return AccessAddressNotification(channel, rssi, access_address)


class RecoverCrcInitCommand(Packet):
    """
    Recover connection's CRCInit value command.
    """
    def __init__(self, access_address):
        # operation 0x00: recover CRCInit
        payload = pack('<BI', 0, access_address)
        super().__init__(Packet.OP_RECOVER, payload, Packet.F_CMD)

class RecoverChmCommand(Packet):
    """
    Recover connection's channel map command.
    """
    def __init__(self, access_address, crcinit, start, stop, timeout=0):
        params = pack('<BIBBBBBI',
            1, # operation type is CHM recovery
            access_address,
            crcinit & 0xff,
            (crcinit & 0xff00) >> 8,
            (crcinit & 0xff0000) >> 16,
            start,
            stop,
            timeout
        )
        super().__init__(Packet.OP_RECOVER, params, Packet.F_CMD)

class RecoverBle5ChmCommand(Packet):
    """
    Recover connection's channel map command.
    """
    def __init__(self, access_address, crcinit, start, stop, timeout=0):
        params = pack('<BIBBBBBI',
            3, # operation type is CHM recovery for BLE v5
            access_address,
            crcinit & 0xff,
            (crcinit & 0xff00) >> 8,
            (crcinit & 0xff0000) >> 16,
            start,
            stop,
            timeout
        )
        super().__init__(Packet.OP_RECOVER, params, Packet.F_CMD)

class RecoverBle5Prng(Packet):
    """
    Recover connection's channel map command.
    """
    def __init__(self, access_address, crcinit, chm, hop_interval):
        chm = bytes([
            chm&0xff,
            (chm&0xff00) >> 8,
            (chm&0xff0000) >> 16,
            (chm&0xff000000) >> 24,
            (chm&0xff00000000) >> 32,
        ])

        params = pack('<BIBBB',
            4, # operation type is PRNG recovery for BLE5
            access_address,
            crcinit & 0xff,
            (crcinit & 0xff00) >> 8,
            (crcinit & 0xff0000) >> 16,
        ) + chm + pack('<BB',
            hop_interval&0xff,
            (hop_interval&0xff00)>>8
        )
        super().__init__(Packet.OP_RECOVER, params, Packet.F_CMD)


class RecoverHopCommand(Packet):
    """
    Recover connection's hopping parameters (interval and increment).
    """
    def __init__(self, access_address, crcinit, chm):
        chm = bytes([
            chm&0xff,
            (chm&0xff00) >> 8,
            (chm&0xff0000) >> 16,
            (chm&0xff000000) >> 24,
            (chm&0xff00000000) >> 32,
        ])
        payload = pack(
            '<BIBBB',
            2,
            access_address,
            crcinit & 0xff,
            (crcinit & 0xff00) >> 8,
            (crcinit & 0xff0000) >> 16,
        ) + chm
        super().__init__(Packet.OP_RECOVER, payload, Packet.F_CMD)

@register_packet(Packet.OP_RECOVER, Packet.F_CMD | Packet.F_RESP)
class RecoverResponse(Packet):
    """
    Recover connection response.
    """
    def __init__(self, operation):
        super().__init__(Packet.OP_RECOVER, bytes(), Packet.F_CMD | Packet.F_RESP)

    @staticmethod
    def from_raw(packet):
        return RecoverResponse(packet.operation)

class RecoverConnectionCommand(Packet):
    """
    Recover connection parameters command.
    """
    def __init__(self, access_address, chm=None, hop=None):
        if chm is None:
            payload = pack('<I', access_address)
            super().__init__(Packet.OP_RECOVER_AA, payload, Packet.F_CMD)
        elif hop is None:
            chm = bytes([
                chm&0xff,
                (chm&0xff00) >> 8,
                (chm&0xff0000) >> 16,
                (chm&0xff000000) >> 24,
                (chm&0xff00000000) >> 32,
            ])
            payload = pack('<I', access_address) + chm
            super().__init__(Packet.OP_RECOVER_AA_CHM, payload, Packet.F_CMD)
        else:
            chm = bytes([
                chm&0xff,
                (chm&0xff00) >> 8,
                (chm&0xff0000) >> 16,
                (chm&0xff000000) >> 24,
                (chm&0xff00000000) >> 32,
            ])
            payload = pack('<I', access_address) + chm + pack('<H', hop)
            super().__init__(Packet.OP_RECOVER_AA_CHM_HOPINTER, payload, Packet.F_CMD)

#@register_packet(Packet.OP_RECOVER_AA, Packet.F_CMD | Packet.F_RESP)
#@register_packet(Packet.OP_RECOVER_AA_CHM, Packet.F_CMD | Packet.F_RESP)
class RecoverConnectionResponse(Packet):
    """
    Recover connection response.
    """
    def __init__(self, operation, access_address=0):
        if operation == Packet.OP_RECOVER_AA:
            super().__init__(Packet.OP_RECOVER_AA, pack('<I', access_address), Packet.F_CMD | Packet.F_RESP)
        elif operation == Packet.OP_RECOVER_AA_CHM:
            super().__init__(Packet.OP_RECOVER_AA_CHM, pack('<I', access_address), Packet.F_CMD | Packet.F_RESP)
        else:
            pass

    @staticmethod
    def from_raw(packet):
        return RecoverConnectionResponse(packet.operation)


@register_packet(Packet.OP_SNIFF_CONREQ, Packet.F_CMD)
class SniffConnReqCommand(Packet):
    """
    Sniff connection request packets command
    """
    def __init__(self, bd_address, channel=37):
        payload = pack('<IHB', bd_address&0xffffffff, bd_address>>32, channel)
        super().__init__(Packet.OP_SNIFF_CONREQ, payload, Packet.F_CMD)

@register_packet(Packet.OP_SNIFF_CONREQ, Packet.F_CMD | Packet.F_RESP)
class SniffConnReqResponse(Packet):
    """
    Sniff connection request response.
    """
    def __init__(self):
        super().__init__(Packet.OP_SNIFF_CONREQ, bytes([]), Packet.F_CMD | Packet.F_RESP)

    @staticmethod
    def from_raw(packet):
        return SniffConnReqResponse()

@register_packet(Packet.OP_SNIFF_CONREQ, Packet.F_CMD)
class EnableJammingCommand(Packet):
    """
    Sniff connection request packets command
    """
    def __init__(self, enabled=False):
        if enabled:
            payload = bytes([1])
        else:
            payload = bytes([0])
        super().__init__(Packet.OP_ENABLE_JAMMING, payload, Packet.F_CMD)

@register_packet(Packet.OP_ENABLE_JAMMING, Packet.F_CMD | Packet.F_RESP)
class EnableJammingResponse(Packet):
    """
    Sniff connection request response.
    """
    def __init__(self):
        super().__init__(Packet.OP_ENABLE_JAMMING, bytes([]), Packet.F_CMD | Packet.F_RESP)

    @staticmethod
    def from_raw(packet):
        return EnableJammingResponse()

@register_packet(Packet.OP_SNIFF_CONREQ, Packet.F_CMD)
class EnableHijackingCommand(Packet):
    """
    Hijacking command.
    """
    def __init__(self, enabled=False):
        if enabled:
            payload = bytes([1])
        else:
            payload = bytes([0])
        super().__init__(Packet.OP_ENABLE_HIJACKING, payload, Packet.F_CMD)

@register_packet(Packet.OP_ENABLE_HIJACKING, Packet.F_CMD | Packet.F_RESP)
class EnableHijackingResponse(Packet):
    """
    Hijacking response.
    """
    def __init__(self):
        super().__init__(Packet.OP_ENABLE_HIJACKING, bytes([]), Packet.F_CMD | Packet.F_RESP)

    @staticmethod
    def from_raw(packet):
        return EnableHijackingResponse()


@register_packet(Packet.OP_SEND_PKT, Packet.F_CMD)
class SendPacketCommand(Packet):
    """
    Send a BLUETOOTH_LE_LL packet.
    """
    def __init__(self, payload):
        super().__init__(Packet.OP_SEND_PKT, payload, Packet.F_CMD)

@register_packet(Packet.OP_SEND_PKT, Packet.F_CMD | Packet.F_RESP)
class SendPacketResponse(Packet):
    """
    Send packet response
    """
    def __init__(self):
        super().__init__(Packet.OP_SEND_PKT, bytes([]), Packet.F_CMD | Packet.F_RESP)

    @staticmethod
    def from_raw(packet):
        return SendPacketResponse()


@register_packet(Packet.N_CRC, Packet.F_NOTIFICATION)
class CrcNotification(Packet):
    """
    Crc notification
    """
    def __init__(self, access_address, crc):
        """
        Constructor
        """
        self.access_address = access_address
        self.crc = crc
        payload = pack('<II', access_address, crc)
        super().__init__(Packet.N_CRC, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, crc = unpack('<II', packet.data[:8])
        return CrcNotification(access_address, crc)

@register_packet(Packet.N_CHANNEL_MAP, Packet.F_NOTIFICATION)
class ChannelMapNotification(Packet):
    """
    Channel map notification.
    """
    def __init__(self, access_address, channel_map):
        """
        Constructor
        """
        self.access_address = access_address
        self.channel_map = channel_map
        #print(hex(self.channel_map))
        payload = pack('<IIB', self.access_address, self.channel_map&0xffffffff, (self.channel_map & 0xff00000000)>>32)
        super().__init__(Packet.N_CHANNEL_MAP, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, chm_l, chm_h = unpack('<IIB', packet.data[:9])
        return ChannelMapNotification(access_address, chm_l | (chm_h << 32))


@register_packet(Packet.N_HOP_INTERVAL, Packet.F_NOTIFICATION)
class HopIntervalNotification(Packet):
    """
    Hop interval notification.
    """
    def __init__(self, access_address, interval):
        self.access_address = access_address
        self.interval = interval
        payload = pack('<IH', access_address, interval)
        super().__init__(Packet.N_HOP_INTERVAL, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, interval = unpack('<IH', packet.data[:6])
        return HopIntervalNotification(access_address, interval)

@register_packet(Packet.N_HOP_INCREMENT, Packet.F_NOTIFICATION)
class HopIncrementNotification(Packet):
    def __init__(self, access_address, increment):
        self.access_address = access_address
        self.increment = increment
        payload = pack('<IB', access_address, increment)
        super().__init__(Packet.N_HOP_INCREMENT, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, increment = unpack('<IB', packet.data[:6])
        return HopIncrementNotification(access_address, increment)

@register_packet(Packet.N_CSA2_PRNG, Packet.F_NOTIFICATION)
class Csa2PrngNotification(Packet):
    def __init__(self, access_address, prng_state):
        self.access_address = access_address
        self.prng_state = prng_state
        payload = pack('<II', access_address, prng_state)
        super().__init__(Packet.N_CSA2_PRNG, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, prng_state = unpack('<II', packet.data[:8])
        return Csa2PrngNotification(access_address, prng_state)


@register_packet(Packet.N_PACKET, Packet.F_NOTIFICATION)
class BlePacketNotification(Packet):
    def __init__(self, data):
        self.data = data
        return super().__init__(Packet.N_PACKET, self.data, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        return BlePacketNotification(packet.data)

@register_packet(Packet.N_PACKET_NORDIC, Packet.F_NOTIFICATION)
class NordicTapPacketNotification(Packet):
    def __init__(self, data):
        """
        Parse nordic header
        """
        self.header_len, self.flags, self.channel = unpack('<BBB', data[:3])
        self.rssi, self.event_counter, self.delta = unpack('<BHI', data[3:10])
        self.data = data
        self.payload = data[10:]
        return super().__init__(Packet.N_PACKET_NORDIC, self.data, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        return NordicTapPacketNotification(packet.data)


@register_packet(Packet.N_HIJACK_STATUS, Packet.F_NOTIFICATION)
class HijackStatusNotification(Packet):
    """
    Hijack status update: error or success.
    """

    def __init__(self, data):
        """
        Parse status.
        """
        self.status = (data[0] == 0x00)
        return super().__init__(Packet.N_HIJACK_STATUS, data, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        return HijackStatusNotification(packet.data)

@register_packet(Packet.N_CONN_LOST, Packet.F_NOTIFICATION)
class ConnectionLostNotification(Packet):
    """
    Connection lost !
    """

    def __init__(self):
        return super().__init__(Packet.N_CONN_LOST, bytes(), Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        return ConnectionLostNotification()

@register_packet(Packet.N_CONN_REQ, Packet.F_NOTIFICATION)
class ConnectionRequestNotification(Packet):
    def __init__(self, hdr_flags, inita, adva, access_address, crc_init, win_size, win_offset, hop_interval, latency, timeout, channel_map, hop_increment):
        self.hdr_flags = hdr_flags
        self.inita = inita
        self.adva = adva
        self.access_address = access_address
        self.crc_init = crc_init
        self.win_size = win_size
        self.win_offset = win_offset
        self.hop_interval = hop_interval
        self.latency = latency
        self.timeout = timeout
        self.channel_map = channel_map
        self.hop_increment = hop_increment
        self.payload = pack(
            '<IHBBHHHHBBBBBB',
            access_address,
            crc_init & 0xffff,
            (crc_init & 0xff0000)>>16,
            win_size,
            win_offset,
            hop_interval,
            latency,
            timeout,
            channel_map[0],
            channel_map[1],
            channel_map[2],
            channel_map[3],
            channel_map[4],
            hop_increment
        )
        return super().__init__(Packet.N_CONN_REQ, self.payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        """
        Parse connection request packet.
        """
        
        # check packet size
        assert packet.data[1] == 0x22

        # save flags
        flags = packet.data[0] & 0xF0

        # extract initA and advA
        inita = packet.data[2:8]
        adva = packet.data[8:14]

        # first 4 bytes are used to store the access address
        access_address = unpack('<I', packet.data[14:18])[0]
        # next 3 bytes contain the CRCInit value
        crc_init = packet.data[18] | (packet.data[19] << 8) | (packet.data[20] << 16)
        # next byte is winsize
        win_size = packet.data[21]
        # next 2 bytes is the winoffset
        win_offset = packet.data[22] | (packet.data[23] << 8)
        # next 2 bytes are the interval
        hop_interval = packet.data[24] | (packet.data[25] << 8)
        # next 2 bytes is the slave latency
        latency = packet.data[26] | (packet.data[27] << 8)
        # next 2 bytes is the supervision timeout
        timeout = packet.data[28] | (packet.data[29] << 8)
        # next 5 bytes is the channel map
        channel_map = packet.data[30:35]
        # next lsb 5 bits is the hop increment
        hop_increment = packet.data[35] & 0x1f
        return ConnectionRequestNotification(
            flags,
            inita,
            adva,
            access_address,
            crc_init,
            win_size,
            win_offset,
            hop_interval,
            latency,
            timeout,
            channel_map,
            hop_increment
        )
