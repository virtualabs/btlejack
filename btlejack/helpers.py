"""
Helpers.
"""

def bytes_to_bd_addr(bd_addr):
    """
    Convert 6-byte values to BD address
    """
    return ':'.join(['%02x'%c for c in bd_addr[::-1]])
