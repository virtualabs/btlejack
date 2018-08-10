"""
Quick'n'dirty Pcap module

This module only provides a specific class able to write
PCAP files with Bluetooth Low Energy Link Layer.
"""
from io import BytesIO
from struct import pack

class PcapBleWriter(object):
    """
    PCAP BLE Link-layer writer.
    """

    DLT =  251  # DLT_BLUETOOTH_LE_LL

    def __init__(self, output=None):
        # open stream
        if output is None:
            self.output = BytesIO()
        else:
            self.output = open(output,'wb')

        # write headers
        self.write_header()

    def write_header(self):
        """
        Write PCAP header.
        """
        header = pack(
            '<IHHIIII',
            0xa1b2c3d4,
            2,
            4,
            0,
            0,
            65535,
            self.DLT
        )
        self.output.write(header)

    def write_packet_header(self, ts_sec, ts_usec, packet_size):
        """
        Write packet header
        """
        pkt_header = pack(
            '<IIII',
            ts_sec,
            ts_usec,
            packet_size,
            packet_size
        )
        self.output.write(pkt_header)

    def payload(self, aa, packet):
        """
        Generates Bluetooth LE LL packet format.
        You must override this method for every inherited
        writer classes.
        """
        return pack('<I', aa) + packet[10:]+ pack('<BBB',0,0,0) # fake CRC for now

    def write_packet(self, ts_sec, ts_usec, aa, packet):
        """
        Add packet to PCAP output.

        Basically, generates payload and encapsulates in a header.
        """
        payload = self.payload(aa, packet)
        self.write_packet_header(ts_sec, ts_usec, len(payload))
        self.output.write(payload)

    def close(self):
        """
        Close PCAP.
        """
        if not isinstance(self.output, BytesIO):
            self.output.close()

class PcapBlePHDRWriter(PcapBleWriter):
    """
    PCAP BLE Link-layer with PHDR.
    """
    DLT = 256 # DLT_BLUETOOTH_LE_LL_WITH_PHDR

    def __init__(self, output=None):
        super().__init__(output=output)

    def payload(self, aa, packet):
        """
        Generate payload with specific header.
        """
        payload_header = pack(
            '<BbbBIH',
            packet[2],
            -40,
            -100,
            0,
            aa,
            0x813
        )
        payload_data = pack('<I', aa) + packet[10:] + pack('<BBB', 0, 0, 0)
        return payload_header + payload_data


class PcapNordicTapWriter(PcapBleWriter):
    """
    PCAP BLE Link-layer writer.
    """

    DLT = 272 # DLT_NORDIC_BLE
    BTLEJACK_ID = 0xDC

    def __init__(self, output=None):
        super().__init__(output=output)
        self.pkt_counter = 0

    def payload(self, aa, packet):
        """
        Create payload with Nordic Tap header.
        """
        payload_data = packet[:10] + pack('<I', aa) + packet[10:]
        payload_data += pack('<BBB', 0, 0, 0)
        pkt_size = len(payload_data)
        if pkt_size > 256:
            pkt_size = 256

        payload_header = pack(
            '<BBBBHB',
            self.BTLEJACK_ID,
            6,
            pkt_size,
            1,
            self.pkt_counter,
            0x06 # EVENT_PACKET
        )

        return payload_header + payload_data[:pkt_size]
