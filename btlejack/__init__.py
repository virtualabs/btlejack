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
from btlejack.ui import (CLIAccessAddressSniffer, CLIConnectionRecovery, CLIConnectionSniffer,
                         CLIAdvertisementsSniffer,CLIAdvertisementsJammer,
                         ForcedTermination, SnifferUpgradeRequired)
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
        dest='devices',
        action='append',
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
        '--sniff_adv',
        '--sniff_advertisements',
        dest='sniff_advertisements',
        type=str,
        help='Sniff advertisements'
    )

    parser.add_argument(
        '--jam_adv',
        '--jam_advertisements',
        dest='jam_advertisements',
        type=str,
        help='Jam advertisements'
    )

    parser.add_argument(
        '--policy_type',
        '--filtering_policy_type',
        dest='policy_type',
        type=str,
        help='Defines the type of filtering policy (blacklist or whitelist) to use'
    )

    parser.add_argument(
        '--accept_invalid_crc',
        dest='accept_invalid_crc',
        action='store_true',
        default=False,
        help='Indicates if the invalid packets are accepted or dropped'
    )


    parser.add_argument(
        '--raw',
        dest='raw',
        default=False,
        action='store_true',
        help='Displays the frames as a succession of bytes.'
    )

    parser.add_argument(
        '--channel',
        dest='channel',
        type=int,
        default=37,
        help='Set channel'
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

    parser.add_argument(
        '-n',
        '--timeout',
        dest='timeout',
        default=0,
        type=int,
        help='Channel map recovery timeout'
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
            supervisor = CLIAccessAddressSniffer(verbose=args.verbose, devices=args.devices)
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

            try:
                supervisor = CLIConnectionRecovery(
                    aa,
                    channel_map=chm,
                    hijack=args.hijack,
                    jamming=args.jamming,
                    hop_interval=hop,
                    crc=crc,
                    output=output,
                    verbose=args.verbose,
                    devices=args.devices,
                    timeout=args.timeout
                )
            except SnifferUpgradeRequired as su:
                print("[i] Quitting, please upgrade your sniffer firmware (-i option if you are using a Micro:Bit)")

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
            try:
                supervisor = CLIConnectionSniffer(
                    bd_addr_int,
                    output=output,
                    verbose=args.verbose,
                    devices=args.devices
                )
            except SnifferUpgradeRequired as su:
                print("[i] Quitting, please upgrade your sniffer firmware (-i option if you are using a Micro:Bit)")
        else:
            print('[!] Wrong Bluetooth Address format: %s' % args.connreq)

    elif args.sniff_advertisements is not None:
        """
        Btlejack allows to use a filtering policy in order to accept or drop specific advertisements.
        It may be useful in order to focus on a specific device, if you want to focus on a specific behaviour, etc.
	The policy can provide a whitelist mode (the rules define the allowed frames) or a blacklist mode
        (the rules define the dropped frames). By default, the whitelist mode is in use, but you can easily change it with
        the --policy_type parameter :
        $ btlejack --policy_type=blacklist --sniff_adv=<rules>

        Multiple rules can be provided, separated by commas: 
        $ btlejack --sniff_adv=<rule1>,<rule2>,<rule3>

        First of all, if you want to accept every received frame, you can use "any" or "FF:FF:FF:FF:FF:FF" :
        $ btlejack --sniff_adv=any

        You may also want to focus on specific devices by providing their BD addresses :
        $ btlejack --sniff_adv=11:22:33:44:55:66
        $ btlejack --sniff_adv=11:22:33:44:55:66,aa:bb:cc:dd:ee:ff

        If you want to focus on some specific type of frames, you can provide their respective name :
        $ btlejack --sniff_adv=SCAN_REQ,SCAN_RSP
        $ btlejack --sniff_adv=CONNECT_REQ

        You can also provide a raw pattern as a *limited* regular expression to match a part of the link layer frame. 
        You can use ? to ignore a specific symbol, and * to specify that some information are missing at the beginning
        of the frame :
        $ btlejack --sniff_adv=?5??665544332211          (matches the CONNECT_REQ transmitted by 11:22:33:44:55:66)
        $ btlejack --sniff_adv=*69546167                 (matches the frames containing the string "iTag")

        If you know where is the position of the pattern in the packet, you can provide it using the syntax <pattern>:<position>:
        $ btlejack --sniff_adv=665544332211aabbccddeeff:2 (matches the SCAN_REQ and CONNECT_REQ transmitted by 11:22:33:44:55:66
                                                           to aa:bb:cc:dd:ee:ff)

        The channel can be provided using --channel=37. If multiple sniffers are found, they are set to different channels to
        monitor every advertisements channels.
 
        """

        result = {"policy_type":"whitelist","rules":[]}

        pattern_list = args.sniff_advertisements.split(",")

        adv_types = {
	        "ADV_IND":{"position":0,"pattern":b"\x00","mask":b"\x0F"},
	        "ADV_DIRECT_IND":{"position":0,"pattern":b"\x01","mask":b"\x0F"},
	        "ADV_NONCONN_IND":{"position":0,"pattern":b"\x02","mask":b"\x0F"},
	        "SCAN_REQ":{"position":0,"pattern":b"\x03","mask":b"\x0F"},
	        "SCAN_RSP":{"position":0,"pattern":b"\x04","mask":b"\x0F"},
	        "CONNECT_REQ":{"position":0,"pattern":b"\x05","mask":b"\x0F"},
	        "ADV_SCAN_IND":{"position":0,"pattern":b"\x06","mask":b"\x0F"}
        }

        # For every pattern in the rule's list :
        for pattern in pattern_list:
            # If pattern is "any" or "FF:FF:FF:FF:FF:FF", the policy type is "blacklist" with no rules.
            if pattern == "any" or pattern.lower() == "ff:ff:ff:ff:ff:ff":
                result["policy_type"] = "blacklist"
                result["rules"] = []
                break
            elif re.match("^([a-fA-F0-9][a-fA-F0-9]:){5}[a-fA-F0-9][a-fA-F0-9]$",pattern):
                # If pattern is a BD address, add a rule matching the pattern anywhere in the frame.
                result["rules"].append({"pattern":bytes.fromhex(''.join([i for i in pattern.split(":")][::-1])),"mask":b"\xFF"*6,"position":0xFF})
            elif re.match("^[a-fA-F0-9\?]*:[0-9]+$",pattern) or re.match("^(\*)?[a-fA-F0-9\?]*(\*)?$",pattern) :
                # If a regexp-like pattern is provided, generate the corresponding rule.
                if ":" in pattern:
                    position = int(pattern.split(":")[1])
                    pattern = pattern.split(":")[0]
                else:
                    if "*"==pattern[0]:
                        position = 0xFF
                    else:
                        position = 0
                value = ""
                mask = ""   
                for char in pattern:
                    if char == "?":
                        value += "0"
                        mask += "0"
                    elif char != "*":
                        value += char
                        mask += "f"
        
                if len(value) % 2 == 0 and len(mask) == len(value):
                    value = bytes.fromhex(value)
                    mask = bytes.fromhex(mask)
                    result["rules"].append({"pattern":value,"mask":mask,"position":position})
            elif pattern in adv_types.keys():
                    # If pattern is a type, use the corresponding rule in adv_types.
                    result["rules"].append(adv_types[pattern])

            # Set the policy according to the --policy_type parameter
            result["policy"] = "whitelist" if args.policy_type is None else (args.policy_type if args.policy_type in ("blacklist","whitelist") else "whitelist")

        try:
            # Instanciate the supervisor
            supervisor = CLIAdvertisementsSniffer(verbose=args.verbose, devices=args.devices,output=output,channel=args.channel,policy=result,accept_invalid_crc=args.accept_invalid_crc, display_raw = args.raw)
        except DeviceError as error:
            print('[!] Please connect a compatible Micro:Bit in order to use BtleJack')
            sys.exit(-1)  

    elif args.jam_advertisements is not None:
        """
        Btlejack allows to reactively jam some advertisements frames according to a specific pattern in the Link Layer frame.
        If you want to reactively jam the advertisements transmitted by a specific target, you can provide its BD address :
        $ btlejack --jam_adv=11:22:33:44:55:66

        If you want to jam a specific pattern, use the syntax <pattern>:<position>. For example, if you want to jam the frames 
        containing aabbcc at the third position, use the following request :
        $ btlejack --jam_adv=aabbcc:3

        Please note that this feature is still experimental. If you want to stop the reactive jamming, you need to reset the 
        device using the physical button (TODO : bugfix). 
        """
        pattern = args.jam_advertisements
        if re.match("^([a-fA-F0-9][a-fA-F0-9]:){5}[a-fA-F0-9][a-fA-F0-9]$",pattern):
            # If the argument provided is an address, generate the corresponding pattern at position 2.
            position = 2
            pattern = bytes.fromhex(pattern.replace(":",""))[::-1]
        elif re.match("^[a-fA-F0-9]*:[0-9]+$",pattern):
            # If the argument provided is a pattern, use it directly.
            position = int(pattern.split(":")[1])
            pattern = bytes.fromhex(pattern.split(":")[0])
        else:
            print("[!] Incorrect pattern, exiting ...")
            sys.exit(-3)

        try:
            # Instanciate the supervisor
            supervisor = CLIAdvertisementsJammer(verbose=args.verbose, devices=args.devices,output=output,channel=args.channel,pattern=pattern,position=position)
        except DeviceError as error:
            print('[!] Please connect a compatible Micro:Bit in order to use BtleJack')
            sys.exit(-1)  

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
