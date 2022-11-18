"""
Btlejack single version module

This module contains the current version of both client and firmware software
(VERSION), but also the release number (RELEASE).

Please note that both client and firmware version shall match or Btlejack will
issue a warning during execution. When implementing new features, or modifying
the internals of either Btlejack's client and firmware, a new version number
should be assigned. Btlejack's firmware shall be updated to reflect this version
number, and also updated into btlejack's package.

The release number allows small modifications due to a release error or update,
such as a wrong packaging or typos.
"""
VERSION = '2.1'
RELEASE = '1'
