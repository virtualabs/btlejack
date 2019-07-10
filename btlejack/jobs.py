"""
BtleJack jobs.
"""

from threading import Thread, Lock

from serial.tools.list_ports import comports

from btlejack.packets import *
from btlejack.interface import AbstractInterface
from btlejack.link import Link

class SingleSnifferInterface(AbstractInterface):
    """
    Single sniffer interface class.

    This class communicates with a single sniffer plugged into the computer.
    """

    def __init__(self, device=None, baudrate=115200):
        """
        Constructor.
        """
        self.link = Link(interface=device, baudrate=115200)
        super().__init__(self.link)

        # reset and request version.
        self.link.reset()
        self.version = self.link.get_version()

    def get_version(self):
        """
        Returns cached version.
        """
        return self.version

    def send_packet(self, packet):
        """
        Send packet if not idling. (synchronous)
        """
        if not self.is_idling():
            self.link.write(
                SendPacketCommand(
                    packet
                )
            )
            return True
        return False

    def set_timeout(self, timeout):
        """
        Set underlying interface timeout (Link).

        @param  float   timeout Timeout to set
        """
        self.link.set_timeout(timeout)

    def scan_access_addresses(self):
        """
        Scan access addresses (synchronous).

        Sends a command switching link into AA scanning mode.
        """
        self.link.write(ScanConnectionsCommand())
        self.link.wait_packet(ScanConnectionsResponse)
        super().scan_access_addresses()

    def recover_crcinit(self, access_address):
        """
        Recover crcinit value based on the provided parameters.

        @param access_address   int     target access address
        """
        self.link.write(RecoverCrcInitCommand(access_address))
        self.link.wait_packet(RecoverResponse)
        super().recover_crcinit()

    def recover_chm(self, access_address, crcinit, start, stop, timeout):
        """
        Recover channel map (distributed over sniffers)

        @param access_address   int     target access address
        @param crcinit          int     CRCInit value
        """
        self.link.write(RecoverChmCommand(access_address, crcinit, start, stop, timeout))
        self.link.wait_packet(RecoverResponse)
        super().recover_chm()

    def recover_hop(self, access_address, crcinit, chm):
        """
        Recover hop interval and increment.

        @param access_address   int     target access address
        @param crcinit          int     CRCInit value
        @param chm              int     Channel map
        """
        self.link.write(RecoverHopCommand(access_address, crcinit, chm))
        self.link.wait_packet(RecoverResponse)
        super().recover_hop()

    def sniff_connection(self, bd_address, channel=37):
        """
        Sniff a specific bd address on a specific channel.
        """
        self.link.write(SniffConnReqCommand(bd_address, channel))
        self.link.wait_packet(SniffConnReqResponse)
        super().sniff_connection()

    def read_packet(self):
        """
        Read packet if one is ready (asynchroous)
        """
        packets = []
        packet = self.link.async_read()
        if packet is not None:
            packets.append(packet)
        return packets

    def enable_advertisements_reactive_jamming(self,channel,pattern,position):
        """
        Enable Advertisements jamming (synchronous).

        Sends a command switching link into Advertisements reactive Jamming mode.
        """
        self.link.write(EnableReactiveJammingCommand(channel=channel,pattern=pattern,position=position))
        self.link.wait_packet(AdvertisementsResponse)
        super().jam_advertisements()
        return True

    def disable_advertisements_reactive_jamming(self):
        """
        Disable Advertisements jamming.

        Sends a command disabling Advertisements reactive jamming mode.
        """
        self.link.write(DisableReactiveJammingCommand())

    def enable_advertisements_sniffing(self,channel):
        """
        Enable Advertisements sniffing (synchronous).

        Sends a command switching link into Advertisements sniffing mode.
        """
        self.link.write(EnableAdvertisementsSniffingCommand(channel))
        pkt = self.link.wait_packet(AdvertisementsResponse)
        super().sniff_advertisements()
        return (pkt.response_type == 0x03 and pkt.status == 0)

    def reset_filtering_policy(self,policy_type="blacklist"):
        """
        Reset filtering policy.

        Sends a command reseting the filtering policy to the provided filtering mode ("whitelist" or "blacklist").
        """
        self.link.write(ResetFilteringPolicyCommand(policy_type))

    def add_rule(self,pattern,mask,position=None):
        """
        Add filtering Rule.

        Sends a command adding a new rule to the filtering policy.
        """
        self.link.write(AddRuleCommand(pattern,mask,position))

        
    def disable_advertisements_sniffing(self):
        """
        Disable Advertisements sniffing (synchronous).

        Sends a command disabling Advertisements sniffing mode.
        """
        self.link.write(DisableAdvertisementsSniffingCommand())

class MultiSnifferInterface(AbstractInterface):
    """
    Multi-sniffer interface class.

    This class allows using as many sniffing devices as we want, and manage
    the corresponding resources.
    """

    def __init__(self, max_number_sniffers=1, baudrate=115200, devices=None):
        super().__init__(None)
        self.interfaces = []

        # Enumerate available interfaces
        self.devices = []
        if devices is None:
            for port in comports():
                if type(port) is tuple:
                    if "VID:PID=0d28:0204" in port[-1]:
                        self.devices.append(port[0])
                elif port.vid == 0x0D28 and port.pid == 0x0204:
                    self.devices.append(port.device)
        else:
            for device in devices:
                self.devices.append(device)

        self.active_link = None
        self.connect(max_number_sniffers, baudrate)
        self.reset()

    def get_version(self):
        """
        Returns cached version.
        """
        versions = [interface.get_version() for interface in self.interfaces]
        return versions

    def connect_device(self, index, baudrate):
        """
        Connect to a specific device with the given baudrate.
        """
        if index < len(self.devices):
            self.interfaces.append(
                SingleSnifferInterface(
                    self.devices[index],
                    baudrate,
                )
            )

    def close(self):
        for link in self.interfaces:
            link.close()

    def connect(self, number, baudrate):
        """
        Connect to `number` devices.
        """
        # Close already existing connections
        self.close()

        # Open `number` connections
        for i in range(number):
            self.connect_device(i, baudrate)

        self.connected = True

    def get(self, index):
        """
        Return an existing Link object.
        """
        if index < len(self.interfaces):
            return self.interfaces[index]

    def get_nb_interfaces(self):
        return len(self.interfaces)

    def get_free_interface(self):
        """
        Return the first free interface.
        """
        for iface in self.interfaces:
            if iface.is_idling():
                return iface
        return None

    def reset(self):
        """
        Reset existing connections.
        """
        for link in self.interfaces:
            link.reset()

    def enable_jamming(self, enabled=False):
        
        if self.active_link is not None:
            self.active_link.enable_jamming(enabled)

    def enable_hijacking(self, enabled=False):
        if self.active_link is not None:
            self.active_link.enable_hijacking(enabled)
        else:
            print('[!] No active link')

    def sniff_connection(self, bd_address):
        """
        Sniff a specific bd address on multiple channels.
        """

        self.active_link = None
        channels = [37, 38, 39]

        # initialize jobs
        for i,link in enumerate(self.interfaces[:len(channels)]):
            link.reset()
            link.set_timeout(0)
            link.sniff_connection(bd_address, channels[i])
        super().sniff_connection()

    def scan_access_addresses(self):
        """
        Scan access addresses (synchronous).

        Sends a command switching link into AA scanning mode.
        """
        # pick an idling interface
        link = self.get_free_interface()
        if link is not None:
            link.set_timeout(0.1)
            link.scan_access_addresses()

    def recover_crcinit(self, access_address):
        """
        Recover a specific connection based on the provided parameters.

        @param access_address   int     target access address
        """
        # pick an idling interface
        link = self.get_free_interface()
        link.set_timeout(0.1)
        if link is not None:
            link.recover_crcinit(access_address)

    def recover_hop(self, access_address, crcinit, chm):
        """
        Recover a specific connection hopping parameters.
        """
        # No collaboration on this one.
        self.reset()
        link = self.get_free_interface()
        link.set_timeout(0.1)
        if link is not None:
            link.recover_hop(access_address, crcinit, chm)
        super().recover_hop()

    def recover_chm(self, access_address, crcinit, timeout=0):
        # compute how many devices we have
        nb_devices = len(self.interfaces)
        self.active_link = None

        # create mapping ranges
        n = int(37 / nb_devices)
        ranges = []
        start = 0
        for i in range(nb_devices):
            if i < (nb_devices-1):
                ranges.append((start, start+n))
                start += n
            else:
                ranges.append((start, 37))

        for i,link in enumerate(self.interfaces):
            link.reset()
            link.set_timeout(0.1)
            link.recover_chm(access_address, crcinit, ranges[i][0], ranges[i][1], timeout)
        super().recover_chm()


    def enable_advertisements_sniffing(self,channel):
        """
        Enable Advertisements sniffing.

        Sends a command switching links into Advertisements sniffing mode.
        """
        if channel == 37:
            channels = [37,38,39]
        elif channel == 38:
            channels = [38,39,37]
        else:
            channels = [39,37,38]
        super().sniff_advertisements()
        for i,link in enumerate(self.interfaces):
            link.enable_advertisements_sniffing(channels[i])
        return True

    def enable_advertisements_reactive_jamming(self,channel,pattern,position):
        """
        Enable Advertisements reactive jamming.

        Sends a command switching links into Advertisements reactive jamming mode.
        """
        if channel == 37:
            channels = [37,38,39]
        elif channel == 38:
            channels = [38,39,37]
        else:
            channels = [39,37,38]
        super().jam_advertisements()
        for i,link in enumerate(self.interfaces):
            link.enable_advertisements_reactive_jamming(channels[i],pattern,position)
        return True

    def disable_advertisements_reactive_jamming(self):
        """
        Disable Advertisements reactive jamming.

        Sends a command disabling Advertisements reactive jamming mode.
        """
        for i,link in enumerate(self.interfaces):
            link.disable_advertisements_reactive_jamming()

    def reset_filtering_policy(self,policy_type="blacklist"):
        """
        Reset filtering policy.

        Sends a command resetting the filtering policies of the connected devices.
        """
        for i,link in enumerate(self.interfaces):
            link.reset_filtering_policy(policy_type)

    def add_rule(self,pattern,mask,position=None):
        """
        Add filtering Rule.

        Sends a command adding a specific rule to the filtering policies of the connected device.
        """
        for i,link in enumerate(self.interfaces):
            link.add_rule(pattern,mask,position)
        
    def disable_advertisements_sniffing(self):
        """
        Disable Advertisements sniffing (synchronous).

        Sends a command disabling Advertisements sniffing mode.
        """
        for i,link in enumerate(self.interfaces):
            link.disable_advertisements_sniffing()

    def read_packet(self):
        """
        Read packet(s) if one is ready (asynchroous)
        """
        packets = []
        if (self.mode == self.MODE_RECOVER_CHM or 
            self.mode == self.MODE_ADVERTISEMENTS_SNIFFING or 
            self.mode == self.MODE_ADVERTISEMENTS_JAMMING):
            for link in self.interfaces:
                if not link.is_idling():
                    pkts = link.read_packet()
                    if len(pkts) > 0:
                        packets.extend(pkts)
            return packets
        else:
            if self.active_link is None:
                for link in self.interfaces:
                    if not link.is_idling():
                        pkts = link.read_packet()
                        if len(pkts) > 0:
                            self.active_link = link
                            self.active_link.link.interface.timeout = 0.1
                            packets.extend(pkts)
                return packets
            else:
                pkts = self.active_link.read_packet()
                if len(pkts) > 0:
                    return pkts
                return []

    def send_packet(self, packet):
        """
        Send a packet on the active link, if any.
        """
        if self.active_link is not None:
            self.active_link.send_packet(packet)
