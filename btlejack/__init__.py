#!/usr/bin/python3
"""
Btlejack, a Bluetooth Low Energy Swiss-army knife

Btlejack is able to sniff newly created and already existing Bluetooth Low
Energy connections, as well as jamming or hijacking them.

It works with a compatible hardware (usually a BBC Micro:Bit) preprogrammed
with the correct firmware.
"""

import os
import signal
import sys
import datetime
import re

from subprocess import check_output
from argparse import ArgumentParser

from btlejack.pcap import PcapBleWriter, PcapNordicTapWriter,  PcapBlePHDRWriter
from btlejack.ui import CLIAccessAddressSniffer, CLIConnectionRecovery, CLIConnectionSniffer, ForcedTermination
from btlejack.helpers import *
from btlejack.link import DeviceError
from btlejack.version import VERSION
from btlejack.session import BtlejackSession, BtlejackSessionError

def bd_address_to_int(bd_address):
    """
    Helper function converting a BD address to the corresponding integer value.
    """
    addr_bytes = [int(v, 16) for v in bd_address.lower().split(':')]
    if len(addr_bytes) != 6:
        return None
    else:
        addr_value =  addr_bytes[0] << (8 * 5)
        addr_value |= addr_bytes[1] << (8 * 4)
        addr_value |= addr_bytes[2] << (8 * 3)
        addr_value |= addr_bytes[3] << (8 * 2)
        addr_value |= addr_bytes[4] << (8 * 1)
        addr_value |= addr_bytes[5] << (8 * 0)
        return addr_value


def main():
    """
    Btlejack main routine for CLI
    """
    parser = ArgumentParser('btlejack')
    parser.add_argument(
        '-d',
        '--device',
        dest='device',
        type=str,
        help='Micro:Bit device serial port'
    )

    parser.add_argument(
        '-s',
        '--scan-connections',
        dest='scan_aa',
        action='store_true',
        default=False,
        help='Scan for active BLE connections'
    )

    parser.add_argument(
        '-f',
        '--follow',
        dest='follow',
        type=str,
        help='Follow an active connection'
    )

    parser.add_argument(
        '-c',
        '--connreq',
        dest='connreq',
        type=str,
        help='Sniff new BTLE connections on multiple channels if possible'
    )

    parser.add_argument(
        '-m',
        '--channel-map',
        dest='chm',
        type=str,
        default=None,
        help='Set channel map'
    )

    parser.add_argument(
        '-p',
        '--hop-interval',
        dest='hop',
        type=int,
        default=None,
        help='Set hop interval'
    )

    parser.add_argument(
        '-v',
        '--verbose',
        dest='verbose',
        action='store_true',
        default=False,
        help='Enable verbose mode'
    )

    parser.add_argument(
        '-o',
        '--output',
        dest='output',
        default=None,
        help='PCAP output file'
    )

    parser.add_argument(
        '-x',
        '--output-format',
        dest='output_format',
        default='pcap',
        help='PCAP output format: `ll_phdr`, `nordic` or `pcap`'
    )

    parser.add_argument(
        '-j',
        '--jamming',
        dest='jamming',
        default=False,
        action='store_true',
        help='Jam an active connection (only performed in conjunction with -f option)'
    )

    parser.add_argument(
        '-t',
        '--hijack',
        dest='hijack',
        default=False,
        action='store_true',
        help='Hijack an active connection (only performed in conjunction with -f option)'
    )

    parser.add_argument(
        '-k',
        '--crc',
        dest='crc',
        help='CRCInit value'
    )

    parser.add_argument(
        '-z',
        '--clear',
        action='store_true',
        dest='flush',
        default=False,
        help='Clear stored connections parameters'
    )

    parser.add_argument(
        '-i',
        '--install',
        action='store_true',
        dest='install',
        help='Install latest version of firmware on every sniffer'
    )

    args = parser.parse_args()
    supervisor = None

    print('BtleJack version %s' % VERSION)
    print('')

    # upgrade sniffers
    if args.install:
        # retrieve the embedded firmware version
        _dir, _filename = os.path.split(__file__)
        fw_path = os.path.join(_dir, "data", "btlejack-fw.hex")


        if os.name == 'posix':
            mount_output = check_output('mount').splitlines()
            mounted_volumes = [x.split()[2] for x in mount_output]
            flashed = 0
            for volume in mounted_volumes:
                if re.match(b'.*MICROBIT[0-9]*$', volume):
                    print('[i] Flashing %s ...' % volume.decode('ascii'))
                    path = os.path.join(volume.decode('ascii'),'fw.hex')
                    fw = open(fw_path,'r').read()
                    # copy our firmware on it
                    with open(path, 'wb') as output:
                        output.write(fw.encode('ascii'))
                    flashed += 1
            if flashed > 0:
                print('[i] Flashed %d devices' % flashed)
            else:
                print('[i] No sniffer found, make sure all your devices are mounted as mass storage devices before flashing.')
            sys.exit(1)
        else:
            print('[!] This feature does not support your operating system, sorry.')

    if args.flush:
        try:
            BtlejackSession.get_instance().clear()
            BtlejackSession.get_instance().save()
            print('[i] Stored connections cleared')
        except BtlejackSessionError as error:
            pass
    else:
        try:
            BtlejackSession.get_instance().load()
        except BtlejackSessionError as error:
            print('[!] Cannot load connections cache')

    # Create output if required
    if args.output is not None:
        if args.output_format.lower().strip() == 'nordic':
            output = PcapNordicTapWriter(args.output)
        elif args.output_format.lower().strip() == 'll_phdr':
            output = PcapBlePHDRWriter(args.output)
        else:
            output = PcapBleWriter(args.output)
    else:
        output = None

    if args.scan_aa:
        try:
            supervisor = CLIAccessAddressSniffer(verbose=args.verbose)
        except DeviceError as error:
            print('[!] Please connect a compatible Micro:Bit in order to use BtleJack')
            sys.exit(-1)

    elif args.follow is not None:
        aa = int(args.follow, 16)
        if args.chm is not None:
            chm = int(args.chm, 16)
        else:
            chm = None
        if args.crc is not None:
            crc = int(args.crc, 16)
        else:
            crc = None

        if args.hop is not None:
            hop = args.hop
        else:
            hop = None
        try:
            cached_parameters = BtlejackSession.get_instance().find_connection(aa)
            if cached_parameters is not None:
                # override parameters with those stored in cache
                for param in cached_parameters:
                    if param == 'crcinit':
                        crc = cached_parameters[param]
                creation_date = datetime.datetime.fromtimestamp(
                    cached_parameters['start']
                ).strftime('%Y-%m-%d %H:%M:%S')
                print('[i] Using cached parameters (created on %s)' % creation_date)

            supervisor = CLIConnectionRecovery(
                aa,
                channel_map=chm,
                hijack=args.hijack,
                jamming=args.jamming,
                hop_interval=hop,
                crc=crc,
                output=output,
                verbose=args.verbose
            )
        except DeviceError as error:
            print('[!] Please connect a compatible Micro:Bit in order to use BtleJack')
            sys.exit(-1)

    elif args.connreq is not None:
        # Support magic word "any" and "*" as wildcards
        if args.connreq.lower() == 'any':
            args.connreq = 'ff:ff:ff:ff:ff:ff'
        bd_addr_int = bd_address_to_int(args.connreq)
        if bd_addr_int is not None:
            # address is okay, feed our sniffer
            supervisor = CLIConnectionSniffer(
                bd_addr_int,
                output=output,
                verbose=args.verbose
            )
        else:
            print('[!] Wrong Bluetooth Address format: %s' % args.connreq)
    elif not args.flush and not args.install:
        print('BtleJack version %s' % VERSION)
        print('')
        parser.print_help()
        sys.exit(-2)


    try:
        # install a handler in case CTRL-C is pressed
        def ctrlc_handler(signum, frame):
            if output is not None:
                print('[i] Stopping capture process ...')
                output.close()
            raise ForcedTermination()

        signal.signal(signal.SIGINT, ctrlc_handler)


        if supervisor is not None:
            while True:
                supervisor.process_packets()
    except ForcedTermination as e:
        print('[i] Quitting')
