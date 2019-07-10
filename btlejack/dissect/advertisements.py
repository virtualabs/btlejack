"""
Advertisements Dissector
"""
from struct import pack, unpack
from ..helpers import *

class Advertisement_Type(object):
    """
    Advertisement type class.
    """
    def __init__(self,payload):
        self.payload = payload

    def __str__(self):
        return self.payload.hex()

    @staticmethod
    def from_bytes(raw):
        return Advertisement_Type(raw)
        
class Advertisement_Adv_Ind(Advertisement_Type):
    """
    ADV_IND class.
    """
    def __init__(self,advA,data):
        self.advA = advA
        self.data = data

    def __str__(self):
        return "ADV_IND|AdvA="+self.advA+"|data="+self.data.hex()

    @staticmethod
    def from_bytes(raw):
        advA = bytes_to_bd_addr(raw[:6])
        data = raw[6:]
        return Advertisement_Adv_Ind(advA,data)
        
class Advertisement_Adv_Direct_Ind(Advertisement_Type):
    """
    ADV_DIRECT_IND class.
    """
    def __init__(self,advA,initA):
        self.advA = advA
        self.initA = initA

    def __str__(self):
        return "ADV_DIRECT_IND|AdvA="+self.advA+"|InitA="+self.initA

    @staticmethod
    def from_bytes(raw):
        advA = bytes_to_bd_addr(raw[:6])
        initA = bytes_to_bd_addr(raw[6:12])
        return Advertisement_Adv_Direct_Ind(advA,initA)

class Advertisement_Adv_NonConn_Ind(Advertisement_Type):
    """
    ADV_NONCONN_IND class.
    """
    def __init__(self):
        pass

    def __str__(self):
        return "ADV_NONCONN_IND"

    @staticmethod
    def from_bytes(raw):
        return Advertisement_Adv_NonConn_Ind()

class Advertisement_Scan_Req(Advertisement_Type):
    """
    SCAN_REQ class.
    """
    def __init__(self,scanA,advA):
        self.scanA = scanA
        self.advA = advA

    def __str__(self):
        return "SCAN_REQ|ScanA="+self.scanA+"|AdvA="+self.advA

    @staticmethod
    def from_bytes(raw):
        scanA = bytes_to_bd_addr(raw[:6])
        advA = bytes_to_bd_addr(raw[6:12])
        return Advertisement_Scan_Req(scanA,advA)

class Advertisement_Scan_Rsp(Advertisement_Type):
    """
    SCAN_RSP class.
    """
    def __init__(self,advA,data):
        self.advA = advA
        self.data = data

    def __str__(self):
        return "SCAN_RSP|AdvA="+self.advA+"|data="+self.data.hex()

    @staticmethod
    def from_bytes(raw):
        advA = bytes_to_bd_addr(raw[:6])
        data = raw[6:]
        return Advertisement_Scan_Rsp(advA,data)

class Advertisement_Connect_Req(Advertisement_Type):
    """
    CONNECT_REQ class.
    """
    def __init__(self,initA,advA,access_address,crc_init,win_size,win_offset,hop_interval,latency,timeout,channel_map,hop_increment):
        self.initA = initA
        self.advA = advA
        self.access_address = access_address
        self.crc_init = crc_init
        self.win_size = win_size
        self.win_offset = win_offset
        self.hop_interval = hop_interval
        self.latency = latency
        self.timeout = timeout
        self.channel_map = channel_map
        self.hop_increment = hop_increment

    def __str__(self):
        return "CONNECT_REQ|InitA="+self.initA+"|AdvA="+self.advA+"|access_address=0x%08x" % self.access_address+"|crc_init=0x%06x" % self.crc_init + "|win_size="+str(self.win_size)+"|win_offset="+str(self.win_offset)+"|hop_interval="+str(self.hop_interval)+"|latency="+str(self.latency*10)+"ms |timeout="+str(self.timeout)+"|channel_map=%02x%02x%02x%02x%02x" % (self.channel_map[4],self.channel_map[3],self.channel_map[2],self.channel_map[1],self.channel_map[0])+"|hop_increment="+str(self.hop_increment)

    @staticmethod
    def from_bytes(raw):
        initA = bytes_to_bd_addr(raw[:6])
        advA = bytes_to_bd_addr(raw[6:12])
        access_address = unpack('<I', raw[12:16])[0]
        crc_init = raw[16] | (raw[17] << 8) | (raw[18] << 16)
        win_size = raw[19]
        win_offset = raw[20] | (raw[21] << 8)
        hop_interval = raw[22] | (raw[23] << 8)
        latency = raw[24] | (raw[25] << 8)
        timeout = raw[26] | (raw[27] << 8)
        channel_map = raw[28:33]
        hop_increment = raw[33] & 0x1f
        return Advertisement_Connect_Req(
                                initA,
                                advA,
                                access_address,
                                crc_init,
                                win_size,
                                win_offset,
                                hop_interval,
                                latency,
                                timeout,
                                channel_map,
                                hop_increment)

class Advertisement_Scan_Ind(Advertisement_Type):
    """
    SCAN_IND class.
    """
    def __init__(self):
        pass

    def __str__(self):
        return "SCAN_IND"

    @staticmethod
    def from_bytes(raw):
        return Advertisement_Scan_Ind()


class Advertisement(object):
    """
    Advertisement management class.
    """

    TYPE = {
        0x00 : Advertisement_Adv_Ind,
        0x01 : Advertisement_Adv_Direct_Ind,
        0x02 : Advertisement_Adv_NonConn_Ind,
        0x03 : Advertisement_Scan_Req,
        0x04 : Advertisement_Scan_Rsp,
        0x05 : Advertisement_Connect_Req,
        0x06 : Advertisement_Scan_Ind

    }

    def __init__(self,adv_type,rxAdd,txAdd,length, payload):
        """
        Assembler.
        """
        self.adv_type = adv_type
        self.rxAdd = rxAdd
        self.txAdd = txAdd
        self.length = length
        self.payload = payload

    def __str__(self):
        rxAdd = "public" if self.rxAdd == 0 else "random"
        txAdd = "public" if self.txAdd == 0 else "random"
        length = str(self.length)
        return "Advertisement(RxAdd="+rxAdd+"|TxAdd="+txAdd+"|Length="+length+"|"+str(self.payload)+")"

    @staticmethod
    def from_bytes(raw):
        rxAdd = raw[0] & 0x80
        txAdd = raw[0] & 0x40
        adv_type = raw[0] & 0x0F
        length = raw[1] & 0x3f
        if adv_type in Advertisement.TYPE:
            return Advertisement(adv_type,rxAdd,txAdd,length,
                Advertisement.TYPE[adv_type].from_bytes(
                    raw[2:]
                )
            )
        else:
            return None


