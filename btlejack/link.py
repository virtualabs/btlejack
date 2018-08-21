"""
Link module.
"""

from serial import Serial
from serial.tools.list_ports import comports
from struct import pack, unpack
from threading import Lock
from btlejack.packets import (Packet, PacketRegistry, ResetCommand,
    VersionCommand, ScanConnectionsCommand, RecoverCrcInitCommand,
    RecoverResponse, ResetResponse, VersionResponse, ScanConnectionsResponse,
    AccessAddressNotification, SniffConnReqCommand, SniffConnReqResponse,
    ConnectionRequestNotification, EnableJammingCommand, EnableJammingResponse,
    EnableHijackingCommand, EnableHijackingResponse)

class DeviceError(Exception):
    """
    Device error
    """
    def __init__(self, message):
        self._message = message
        super().__init__(self)

    def __str__(self):
        return "<DeviceError message='%s'" % self._message

    def __repr__(self):
        return str(self)


class Link(object):
    """
    Serial link with the BBC Micro:Bit
    """

    def __init__(self, interface=None, baudrate=115200):
        self.lock = Lock()

        # Pick the first serial port that matches a Micro:Bit
        # if no interface is provided
        if interface is None:
            for port in comports():
                if type(port) is tuple:
                    if "VID:PID=0d28:0204" in port[-1]:
                        interface = port[0]
                        break
                elif port.vid == 0x0D28 and port.pid == 0x0204:
                    interface = port.device
                    break

        # If no interface found, we cannot do anything as we need at least
        # one Micro:bit device connected.
        if interface is None:
            raise DeviceError('No Micro:Bit connected')

        # If an interface was found, continue
        self.interface = Serial(interface, baudrate, timeout=0)
        self.rx_buffer = bytes()

    def set_timeout(self, timeout):
        """
        Set interface timeout.

        @param timeout  float   New timeout to set
        """
        if self.interface is not None:
            self.interface.timeout = timeout

    def close(self):
        """
        Close serial port.
        """
        if self.interface:
            self.interface.close()

    def is_open(self):
        """
        Check if a serial port is open.
        """
        return (not self.interface.is_open)

    def readable(self):
        """
        Determine if there is some data to read from serial.
        """
        return self.interface.in_waiting

    def write(self, packet):
        """
        Send a packet
        """
        self.lock.acquire()
        raw_pkt = packet.toBytes()
        result = self.interface.write(raw_pkt)
        self.lock.release()
        return result

    def async_read(self):
        """
        Read packet from serial.
        """
        self.lock.acquire()

        # append data
        self.rx_buffer += self.interface.read()

        # ensure first byte start with 0xbc
        if len(self.rx_buffer) > 0:
            if self.rx_buffer[0] != 0xbc:
                try:
                    pkt_start = self.rx_buffer.index(0xbc)
                    self.rx_buffer = self.rx_buffer[pkt_start:]
                except ValueError:
                    self.rx_buffer = bytes()

        # check if we got a valid packet
        if len(self.rx_buffer) >= 4:
            pkt_size = unpack('<H', self.rx_buffer[2:4])[0]
            # check if we got a complete packet
            if len(self.rx_buffer) >= (pkt_size + 5):
                # yep, parse this packet
                packet = Packet.fromBytes(self.rx_buffer[:pkt_size+5])
                self.rx_buffer = self.rx_buffer[pkt_size+5:]
                self.lock.release()
                return packet

        # otherwise, return None
        self.lock.release()
        return None

    def read(self):
        """
        Synchronous read of packets.
        """
        packet = None
        while packet is None:
            packet = self.async_read()
        return packet

    def wait_packet(self, clazz):
        """
        Wait for a specific packet type.
        """
        while True:
            pkt = PacketRegistry.decode(self.read())
            if isinstance(pkt, clazz):
                return pkt

    def reset(self):
        """
        Reset sniffer.
        """
        pkt = ResetCommand()
        self.write(pkt)
        self.wait_packet(ResetResponse)

    def get_version(self):
        """
        Get sniffer version.
        """
        self.write(VersionCommand())
        pkt = self.wait_packet(VersionResponse)
        return (pkt.major, pkt.minor)

    def enable_jamming(self, enabled=False):
        """
        Enable jamming.
        """
        self.write(EnableJammingCommand(enabled))
        pkt = self.wait_packet(EnableJammingResponse)

    def enable_hijacking(self, enabled=False):
        """
        Enable hijacking (enables jamming too :p).
        """
        self.write(EnableHijackingCommand(enabled))
        pkt = self.wait_packet(EnableHijackingResponse)

    def scan_access_addresses(self):
        self.write(ScanConnectionsCommand())
        self.wait_packet(ScanConnectionsResponse)
        """
        # loop on access address notifications
        while True:
            pkt = PacketRegistry.decode(self.read())
            if isinstance(pkt, AccessAddressNotification):
                yield pkt
        """

    def recover_connection(self, access_address, channel_map=None, hop_interval=None):
        """
        Recover an existing connection.
        """
        self.write(RecoverCrcInitCommand(access_address, channel_map, hop_interval))
        self.wait_packet(RecoverResponse)
        while True:
            # get packet
            pkt = PacketRegistry.decode(self.read())
            yield pkt

    def sniff_connection(self, bd_address, channel=37):
        """
        Listen for packets
        """
        p = SniffConnReqCommand(bd_address, channel)
        self.write(p)
        self.wait_packet(SniffConnReqResponse)
        """
        while True:
            # get packet
            pkt = PacketRegistry.decode(self.read())
            yield pkt
        """
