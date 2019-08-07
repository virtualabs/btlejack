"""
Packet interface.

Links the link layer to UI.
"""

class AbstractInterface(object):
    """
    Sniffer/Hijacker abstract class.
    """

    MODE_DISCONNECTED = -1
    MODE_IDLE = 0
    MODE_SCANNING = 1
    MODE_RECOVER = 2
    MODE_SNIFFING = 3
    MODE_CCHM = 4
    MODE_RECOVER_CRC = 5
    MODE_RECOVER_CHM = 6
    MODE_RECOVER_HOP = 7
    MODE_RECOVER_PRNG = 8

    def __init__(self, link):
        """
        Constructor
        """
        # default mode is MODE_IDLE
        self.mode = self.MODE_IDLE
        self.link = link

    def is_idling(self):
        return (self.mode == self.MODE_IDLE)

    def is_scanning(self):
        return (self.mode == self.MODE_SCANNING)

    def is_recovering(self):
        return (self.mode == self.MODE_RECOVER)

    def is_sniffing(self):
        return (self.mode == self.MODE_SNIFFING)

    def get_link(self):
        return self.link

    def close(self):
        return self.link.close()

    def reset(self):
        """
        Reset sniffer.
        """
        self.link.reset()
        self.mode = self.MODE_IDLE

    def get_version(self):
        """
        Return sniffer version as tuple.
        """
        return self.link.get_version()

    def enable_jamming(self, enabled=False):
        """
        Enable jamming
        """
        return self.link.enable_jamming(enabled)

    def enable_hijacking(self, enabled=False):
        """
        Enable hijacking.
        """
        return self.link.enable_hijacking(enabled)

    def scan_access_addresses(self):
        """
        Switch the link in scanning mode.
        """
        self.mode = self.MODE_SCANNING

    def recover_crcinit(self):
        """
        Switch the link in crcinit recovery mode.
        """
        self.mode = self.MODE_RECOVER_CRC

    def recover_chm(self):
        """
        Switch the link in channel map recovery mode.
        """
        self.mode = self.MODE_RECOVER_CHM

    def recover_hop(self):
        """
        Switch the link in hop parameters recovery mode.
        """
        self.mode = self.MODE_RECOVER_HOP

    def recover_connection(self):
        """
        Switch the link in connection recovery mode.
        """
        self.mode = self.MODE_RECOVER

    def recover_prng(self):
        """
        Switch the link in CSA2 PRNG recovery mode.
        """
        self.mode = self.MODE_RECOVER_PRNG

    def sniff_connection(self):
        """
        Switch the link in connection sniffing mode.
        """
        self.mode = self.MODE_SNIFFING

    def collab_channel_map(self):
        """
        Switch to collaborative channel mapping mode.
        """
        self.mode = self.MODE_CCHM

    def read_packet(self):
        """
        Read a packet from the underlying link.

        Returns None if no packet has been received, or a packet
        object if one has been received.
        """
        return None
