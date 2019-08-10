version 2.0

* Added support for BLE 5 1Mbps Uncoded PHY with CSA2
* Added a new option (-w) to allow live analysis with wireshark through FIFO (issue #39)
* Fixed multiple bugs (including #44)

version 1.3

* Added a new option (-n) to control channel map recovery timeout
* Fixed a bug in the channel mapping process
* Fixed a bug in the main program, causing trouble when hijacking

version 1.2.1

* Allowed more than 3 sniffers in active connection sniffing mode

version 1.2.0

* Added connection loss detection to Btlejack's firmware
* Cleaned up the disconnection routine when hijacking
