##
## This file is part of the libsigrokdecode project.
##
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd
import struct


# ============================================================
# Tables / Constants
# ============================================================

# ---- MCTP ----
MCTP_MSG_TYPES = {
    0x00: "Control",
    0x01: "PLDM",
    0x05: "SPDM",
    0x04: "NVMe-MI",
}

# ---- NVMe‑MI message types ----
NVME_MI_MSG_TYPES = {
    0x00: "Control Primitive",
    0x01: "NVMe MI Command",
    0x02: "NVMe Admin Command",
    0x03: "Reserved",
    0x04: "PCIe Command",
    0x05: "Asynchronous Event",
}

# ---- NVMe MI Opcodes ----
NVME_CONTROL_OPCODES = {
    0x00: "Pause",
    0x01: "Resume",
    0x02: "Abort",
    0x03: "Get State",
    0x04: "Replay",
}

# ---- NVMe MI Opcodes ----
NVME_MI_OPCODES = {
    0x00: "Read NVMe-MI Data Structure",
    0x01: "NVM Subsystem Health Status Poll",
    0x02: "Controller Health Status Poll",
    0x03: "Configuration Set",
    0x04: "Configuration Get",
    0x05: "VPD Read",
    0x06: "VPD Write",
    0x07: "Reset",
    0x08: "SES Receive",
    0x09: "SES Send",
    0x0A: "MEB Read",
    0x0B: "MEB Write",
    0x0C: "Shutdown",
}

# ---- NVMe Admin Opcodes ----
NVME_ADMIN_OPCODES = {
    0x02: "Get Log Page",
    0x06: "Identify",
    0x09: "Set Features",
    0x0A: "Get Features",
    0x0D: "Namespace Management",
    0x10: "Firmware Commit",
    0x11: "Firmware Image Download",
    0x14: "Device Self-Test",
    0x15: "Namespace attachment",
    0x1C: "Virtualization Management",
    0x20: "Capacity Management",
    0x24: "Lockdown",
    0x28: "Clear Exported NVM Resource Configuration",
    0x2A: "Create Exported NVM Subsystem",
    0x2D: "Manage Exported NVM Subsystem",
    0x31: "Manage Exported Namespace",
    0x35: "Manage Exported Port",
    0x80: "Format NVM",
    0x81: "Security Send",
    0x82: "Security Receive",
    0x84: "Sanitize",
    0x86: "Get LBA Status",
    0x8C: "Sanitize Namespace",
}

NVME_STATUS = {
    # Generic success
    0x00: "Success",

    # Generic command errors
    0x01: "Invalid Command Opcode",
    0x02: "Invalid Field",
    0x03: "Command ID Conflict",
    0x04: "Data Transfer Error",
    0x05: "Commands Aborted due to Power Loss Notification",
    0x06: "Internal Device Error",
    0x07: "Command Abort Requested",
    0x08: "Command Aborted due to SQ Deletion",
    0x09: "Command Aborted due to Failed Fused Command",
    0x0A: "Command Aborted due to Missing Fused Command",
    0x0B: "Invalid Namespace or Format",
    0x0C: "Command Sequence Error",
    0x0D: "Invalid SGL Last Segment Descriptor",
    0x0E: "Invalid Number of SGL Descriptors",
    0x0F: "Data SGL Length Invalid",
    0x10: "Metadata SGL Length Invalid",
    0x11: "SGL Descriptor Type Invalid",
    0x12: "Invalid Use of Controller Memory Buffer",

    # Data integrity errors
    0x80: "Internal Error",
    0x80: "Write Fault",
    0x81: "Unrecovered Read Error",
    0x82: "End-to-end Guard Check Error",
    0x83: "End-to-end Application Tag Check Error",
    0x84: "End-to-end Reference Tag Check Error",
    0x85: "Compare Failure",
    0x86: "Access Denied",

    # Media / storage errors
    0xC0: "LBA Out of Range",
    0xC1: "Capacity Exceeded",
    0xC2: "Namespace Not Ready",
    0xC3: "Reservation Conflict",
    0xC4: "Format In Progress",

    # NVMe-MI specific / transport-related
    0xE0: "Invalid Parameter",
    0xE1: "Invalid Packet",
    0xE2: "Invalid Length",
    0xE3: "Invalid Control Primitive",
    0xE4: "Access Denied (MI)",
    0xE5: "VPD Update Failed",
    0xE6: "Invalid Endpoint",
    0xE7: "Management Endpoint Busy",

}

NVME_MI_STATUS = {
    0x00: "Success",
    0x01: "More Processing Required",
    0x02: "Internal Error",
    0x03: "Invalid Command Opcode",
    0x04: "Invalid Parameter",
    0x05: "Invalid Command Size",
    0x06: "Invalid Command Input Data",
    0x07: "Access Denied",
    0x07: "Unable to abort",
    
    # 0x09–0x1F reserved

    0x20: "VPD Updates Exceeded",
    0x21: "PCIe Inaccessible",
    0x22: "Management Endpoint Buffer Cleared Due to Sanitize",
    0x23: "Enclosure Services Failure",
    0x24: "Enclosure Services Transfer Failure",
    0x25: "Enclosure Failure",
    0x26: "Enclosure Services Transfer Refused",
    0x27: "Unsupported Enclosure Function",
    0x28: "Enclosure Services Unavailable",
    0x29: "Enclosure Degraded",
    0x2A: "Sanitize In Progress",
    
    # 0x2B–0xDF reserved
    # 0xE0–0xFF also vendor specific
}

ELEMENT_DESCRIPTOR_TYPE = {
    1 : "Extended Element Descriptor",
    2 : "Upstream Connector Element Descriptor",
    3 : "Expansion Connector Element Descriptor",
    4 : "Label Element Descriptor",
    5 : "2-Wire Mux Element Descriptor",
    6 : "PCIe Switch Element Descriptor",
    7 : "NVM Subsystem Element Descriptor",
    8 : "FRU Information Device Element Descriptor",
    240 : "Vendor specific",
}

PCIE_LINK_SPEED_BITS = {
    5: "64.0 GT/s Support",
    4: "32.0 GT/s Support",
    3: "16.0 GT/s Support",
    2: "8.0 GT/s Support",
    1: "5.0 GT/s Support",
    0: "2.5 GT/s Support",
}

PCIE_MAX_LINK_WIDTH = {
    1 : "PCIe x1",
    2 : "PCIe x2",
    4 : "PCIe x4",
    8 : "PCIe x8",
    12 : "PCIe x12",
    16 : "PCIe x16",
    32 : "PCIe x32",
}

UPD_FORM_FACTOR = {
    0: ["Unspecified", "Other – unknown"],
    1: ["PCIe", "Integrated"],
    2: ["PCIe", "Other – unknown"],

    #"3-15": ["Reserved", None],

    16: ["PCIe", "2.5” Form Factor – unknown"],
    17: ["PCIe", "2.5” Form Factor – PCI Express SFF-8639 Module (U.2) 15 mm"],
    18: ["PCIe", "2.5” Form Factor – PCI Express SFF-8639 Module (U.2) 7 mm"],
    19: ["PCIe", "2.5” Form Factor – (SFF-TA-1001) 15 mm"],
    20: ["PCIe", "2.5” Form Factor – (SFF-TA-1001) 7 mm"],

    #"21-31": ["Reserved", None],

    32: ["PCIe", "CEM add in card – unknown"],
    33: ["PCIe", "CEM add in card – Low Profile (HHHL)"],
    34: ["PCIe", "CEM add in card – Standard Height Half Length (FHHL)"],
    35: ["PCIe", "CEM add in card – Standard Height Full Length (FHFL)"],

    #"36-47": ["Reserved", None],

    48: ["PCIe", "M.2 module – unknown"],
    49: ["PCIe", "M.2 module – 2230"],
    50: ["PCIe", "M.2 module – 2242"],
    51: ["PCIe", "M.2 module – 2260"],
    52: ["PCIe", "M.2 module – 2280"],
    53: ["PCIe", "M.2 module – 22110"],

    #"54-63": ["Reserved", None],

    64: ["PCIe", "BGA SSD – unknown"],
    65: ["PCIe", "BGA SSD – 16 x 20mm (M.2 Type 1620)"],
    66: ["PCIe", "BGA SSD – 11.5 x 13mm (M.2 Type 1113)"],

    #"67-79": ["Reserved", None],

    80: ["PCIe", "Enterprise & Datacenter SSD Form Factor – unknown"],
    81: ["PCIe", "E1.S - (SFF-TA-1006) 5.9 mm"],
    82: ["PCIe", "E1.S - (SFF-TA-1006) 8 mm"],
    83: ["PCIe", "E1.L - (SFF-TA-1007) 9.5 mm"],
    84: ["PCIe", "E1.L - (SFF-TA-1007) 18 mm"],
    85: ["PCIe", "E3.S - (SFF-TA-1008) 7.5 mm"],
    86: ["PCIe", "E3.S - (SFF-TA-1008) 16.8 mm"],
    87: ["PCIe", "E3.L - (SFF-TA-1008) 7.5 mm"],
    88: ["PCIe", "E3.L - (SFF-TA-1008) 16.8 mm"],
    89: ["PCIe", "E1.S - (SFF-TA-1006) 9.5 mm"],
    90: ["PCIe", "E1.S - (SFF-TA-1006) 15 mm"],
    91: ["PCIe", "E1.S - (SFF-TA-1006) 25 mm"],

    #"92-95": ["Reserved", None],

    96: ["Ethernet", "Other – unknown"],
    97: ["Ethernet", "2.5” Form Factor – (Native NVMe-oF Drive) 15 mm"],
    98: ["Ethernet", "2.5” Form Factor – (Native NVMe-oF Drive) 7 mm"],
    99: ["Ethernet", "E3.S – (Native NVMe-oF Drive) 7.5 mm"],
    100: ["Ethernet", "E3.S – (Native NVMe-oF Drive) 16.8 mm"],

    #"101-239": ["Reserved", None],

    #"240-255": ["Vendor Specific", "Vendor Specific"]
}

DIC_SMBUS_ADDRESS_7Bits = {
    # Reserved and pre-assigned SMBus addresses, Appendix C - SMBus Device Address Assignments
    0x00 : "General Call Address",
    0x01 : "CBUS address",
    0x02 : "Address reserved for different bus format",
    0x03 : "Reserved for future use",

    # HS Mode Controller Code
    0x04 : "HS Mode Controller Code 0",
    0x05 : "HS Mode Controller Code 1",
    0x06 : "HS Mode Controller Code 2",
    0x07 : "HS Mode Controller Code 3",

    0x08 : "SMBus Host Address",
    0x09 : "Smart Battery Charger",
    0x0A : "Smart Battery Selector/Smart Battery System Manager",
    0x0B : "Smart Battery",
    0x0C : "SMBus Alert Response Address",
    0x28 : "PMBus ZONE READ",

    # This address may be reassigned in future versions of the SMBus specification.
    0x2C : "LCD Contrast Controller",
    0x2D : "CCFL Backlight Driver",
    0x40 : "PCMCIA Socket Controllers 0",
    0x41 : "PCMCIA Socket Controllers 1",
    0x42 : "PCMCIA Socket Controllers 2",
    0x43 : "PCMCIA Socket Controllers 3",
    0x44 : "(VGA) Graphics Controller",
    
    0x2F : "PMBus™ ZONE WRITE",
    
    #Prototype Address
    0x48 : "Prototype Address 0",
    0x49 : "Prototype Address 1",
    0x4A : "Prototype Address 2",
    0x4B : "Prototype Address 3",

    # SMBus Device Default Address
    0x61 : "SMBus Device Default Address",

    # NVMe MI elements
    0x53 : "VPD Data",
    0x52 : "FRU Information Device",
    0x1D : "2-Wire Management Endpoint",
    0x74 : "2-Wire Mux",
    0x6A : "Basic Management Command",
}

DIC_SMBUS_ADDRESS_8Bits = {
    # Reserved and pre-assigned SMBus addresses, Appendix C - SMBus Device Address Assignments
    0x00 : "General Call Address",
    0x01 : "START byte",
    0x02 : "CBUS address",
    0x04 : "Address reserved for different bus format",
    0x06 : "Reserved for future use",
    
    # HS Mode Controller Code
    0x08 : "HS Mode Controller Code 0",
    0x0A : "HS Mode Controller Code 1",
    0x0C : "HS Mode Controller Code 2",
    0x0E : "HS Mode Controller Code 3",
    
    0x10 : "SMBus Host Address",
    0x12 : "Smart Battery Charger",
    0x14 : "Smart Battery Selector/Smart Battery System Manager",
    0x16 : "Smart Battery",
    0x19 : "SMBus Alert Response Address",
    0x18 : "Invalid. Bit[0]=0 is not permitted",
    0x51 : "PMBus ZONE READ",
    
    # This address may be reassigned in future versions of the SMBus specification.
    0x58 : "LCD Contrast Controller",
    0x5A : "CCFL Backlight Driver",
    0x80 : "PCMCIA Socket Controllers 0",
    0x82 : "PCMCIA Socket Controllers 1",
    0x84 : "PCMCIA Socket Controllers 2",
    0x86 : "PCMCIA Socket Controllers 3",
    0x88 : "(VGA) Graphics Controller",
    
    0x5E : "PMBus™ ZONE WRITE",

    # Prototype Address
    0x90 : "Prototype Address 0",
    0x92 : "Prototype Address 1",
    0x94 : "Prototype Address 2",
    0x96 : "Prototype Address 3",
    
    # SMBus Device Default Address
    0xC2 : "SMBus Device Default Address",
    
    # NVMe MI elements
    0xA6 : "VPD Data",
    0xA4 : "FRU Information Device",
    0x3A : "2-Wire Management Endpoint",
    0xE8 : "2-Wire Mux",
    0xD4 : "Basic Management Command",

}

DicAnnotations = {
    'START':           [0, 'Start',         'S'],
    'ADDRESS READ':    [1, 'Address read',  'AR'],
    'DATA READ':       [2, 'Data read',     'DR'],
    'MCTP TRANS':      [3, 'MCTP trans',    'MT'],
    'MCTP HEADER':     [4, 'MCTP Header',   'MH'],
    'NVMeMI HEADER':   [5, 'NVMe-MI HEADER',    'NH'],
    'NVMeMI PAYLOAD':  [4, 'NVMe-MI Payload',   'Py'],
    'PEC':             [7, 'PEC',           'PC'],
    'STOP':            [8, 'Stop',          'ST'],
    'ACK':             [9, 'ACK',           'A'],
    'NACK':            [10, 'NACK',          'N'],
    'BIT':             [11, 'Bit',           'B'],
    'START REPEAT':    [18, 'Start repeat', 'Sr'],
}


# ============================================================
# Decoder
# ============================================================

class Decoder(srd.Decoder):
    api_version = 3
    id = 'smbus_mctp_nvme_mi'
    name = 'SMBus MCTP NVMe‑MI'
    longname = 'SMBus + MCTP + NVMe‑MI'
    desc = 'Full NVMe‑MI decode over MCTP/SMBus'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['SMBUS']
    tags = ['Storage', 'NVMe', 'MCTP', 'SMBUS']
    channels = (
        {'id': 'scl', 'name': 'SCL', 'desc': 'Serial clock line'},
        {'id': 'sda', 'name': 'SDA', 'desc': 'Serial data line'},
    )
    options = (
        {'id': 'address_format', 'desc': 'Displayed slave address format',
            'default': 'shifted', 'values': ('shifted', 'unshifted')},
    )
    annotations = (
        ('start', 'START'),
        ('addr', 'Address'),
        ('data', 'Data'),
        ('mctp_hdr', 'MCTP Transport Header'),
        ('mctp_msg', 'MCTP Message Header'),
        #5
        ('mi_hdr', 'NVMe-MI Header'),
        ('mi_payload', 'NVMe-MI Payload'),
        ('pec', 'PEC'),
        ('stop', 'STOP'),
        ('ack', 'ACK'),
        # 10
        ('nack', 'NACK'),
        ('bit', 'Data/address bit'),
        ('SMBUS', 'SMBUS'),
        ('MCTP', 'MCTP'),
        ('NVMeMI', 'NVMe-MI'),
        #15
        ('AddrSMBus', 'Address SMBus'),
        ('Payload', 'Payload'),
        ('rw-bit', 'Read/write bit'),        
        ('repeat-start', 'Repeat start condition'),
    )
    annotation_rows = (
        ('smbus', 'SMBus', (0, 1, 2, 8, 9, 10, 18, 19)),
        ('mctp', 'MCTP', (3, 4)),
        ('nvme', 'NVMe-MI', (5, 6)),
        ('Sec', 'Hdrs/Dwords', (7, 12, 13, 14, 16)),
        ('bits-bytes', 'Bits/bytes', (15, 17)),
        ('bits', 'Bits', (11,)),        
    )
    binary = (
        ('address-read', 'Address read'),
        ('address-write', 'Address write'),
        ('data-read', 'Data read'),
        ('data-write', 'Data write'),
    )

    # ---------------------------------------------------------
    # Init / Reset
    # ---------------------------------------------------------
    def __init__(self):
        self.reset()

    def reset(self):
        self.error = 0
        self.packets = []
        self.bytebuf = []
        self.bytesXbits = []
        self.samplerate = None
        self.ss = self.es = self.ss_byte = -1
        self.bitcount = 0
        self.databyte = 0
        self.pdu_start = None
        self.pdu_bits = 0
        self.state = 'FIND START'
        self.is_repeat_start = 0
        self.wr = -1
        self.bits = []

    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value

    def start(self):
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_binary = self.register(srd.OUTPUT_BINARY)
        self.out_bitrate = self.register(srd.OUTPUT_META, meta=(int, 'Bitrate', 'Bitrate from Start bit to Stop bit'))

    def putx(self, data):
        self.put(self.ss, self.es, self.out_ann, data)

    def putp(self, data):
        self.put(self.ss, self.es, self.out_python, data)

    def putb(self, data):
        self.put(self.ss, self.es, self.out_binary, data)

    def putbits(self, bit1, bit2, bits, data):
        self.put(bits[bit1][1], bits[bit2][2], self.out_ann, data)

    def packet_append(self):
        self.packets.append([self.ss, self.es, self.cmd, self.databyte, self.bits])

    def handle_start(self, pins):
        self.ss, self.es = self.samplenum, self.samplenum
        self.pdu_start = self.samplenum
        self.pdu_bits = 0
        cmd = 'START REPEAT' if (self.is_repeat_start == 1) else 'START'
        if cmd == 'START REPEAT':
            self.put_payload_bytes()
        self.putp([cmd, None])
        self.putx([DicAnnotations[cmd][0], DicAnnotations[cmd][1:]])
        self.reset()
        self.state = 'FIND ADDRESS'
        self.bitcount = self.databyte = 0
        self.is_repeat_start = 1
        self.wr = -1
        self.bits = []

    def put_address_word(self, bits):
        s = (bits >> 0x1) & 0x7F
        s1 = 'read' if (bits & 0x01) == 1 else 'write'
        s2 = 'R' if (bits & 0x01) == 1 else 'W'

    def handle_smbus_parser(self, data):
        smbus = {
            0 :     ['DSA',                 data[0],                        "SMBus Destination Slave Address"],
            1 :     ['PTL',                 data[1],                        "Command Code"],
            2 :     ['LEN',                 data[2],                        "Byte Count"],
            3 :     ['SSA',                 data[3],                        "SMBus Source Slave address"],
        }
        return smbus
        
    def handle_smbus(self):
        Data = [self.packets[j][3] for j in range(0, 4)]
        smbus = self.handle_smbus_parser(Data)

        self.put(self.packets[0][0], self.packets[3][1], self.out_ann, [12, ['SMBus header ', 'SMBus header', 'SBH']])
        self.put(self.packets[0][0], self.packets[3][1], self.out_ann, [3, 
        ['%s: %02X | %s: %02X | %s: %02X | %s: %02X' % (smbus[0][2], smbus[0][1], smbus[1][2], smbus[1][1], smbus[2][2], smbus[2][1], smbus[3][2], smbus[3][1]), 
        '%s: %02X | %s: %02X | %s: %02X | %s: %02X' % (smbus[0][0], smbus[0][1], smbus[1][0], smbus[1][1], smbus[2][0], smbus[2][1], smbus[3][0], smbus[3][1]), 
        '%s | %s | %s | %s' % (smbus[0][0], smbus[1][0], smbus[2][0], smbus[3][0]), 
        'S']])
        
    def handle_mctp_parser(self, data):
        mctp = {
            0 :     ["HdrVer",             data[0],                        "MCTP version"],
            1 :     ["DstID",               data[1],                        "Destination endpoint ID"],
            2 :     ["SstID",               data[2],                        "Source endpoint ID"],
            3 :     ["Flg",                 data[3],                        "flags"],
            4 :     ["SOM",                 bool(data[3] & 0x80),           "   Start Of Message"],
            5 :     ["EOM",                 bool(data[3] & 0x40),           "   End Of Message"],
            6 :     ["PSN",                 (data[3] >> 4) & 0x3,           "   Packet sequence number"],
            7 :     ["TO",                  bool(data[3] & 0x8),            "   Tag Owner"],
            8 :     ["MT",                  (data[3] & 0x7),                "   Message Tag"],
        }
        
        return mctp

    def handle_mctp(self):
        Data = [self.packets[j][3] for j in range(4, 8)]
        mctp = self.handle_mctp_parser(Data)
        
        self.SOM = mctp[4][1]
        self.EOM = mctp[5][1]
        
        self.put(self.packets[4][0], self.packets[7][1], self.out_ann, [13, ['MCTP Header', 'MCTP', 'MH']])
        self.put(self.packets[4][0], self.packets[7][1], self.out_ann, [4, 
        ['%s: %02X | %s: %02X → %s %02X | %s %r %s %r %s %02X %s %d %s %02X' % (mctp[0][2], mctp[0][1], mctp[1][2], mctp[1][1], mctp[2][2], mctp[2][1], mctp[4][2], mctp[4][1], mctp[5][2], mctp[5][1], mctp[6][2], mctp[6][1], mctp[7][2], mctp[7][1], mctp[8][2], mctp[8][1]), 
        '%s: %02X | %s: %02X → %s %02X | %s %r %s %r %s %02X %s %d %s %02X' % (mctp[0][0], mctp[0][1], mctp[1][0], mctp[1][1], mctp[2][0], mctp[2][1], mctp[4][0], mctp[4][1], mctp[5][0], mctp[5][1], mctp[6][0], mctp[6][1], mctp[7][0], mctp[7][1], mctp[8][0], mctp[8][1]), 
        '%s | %s → %s | %s' % (mctp[0][0], mctp[1][0], mctp[2][0], mctp[3][0]), 
        'Mc']])

    def handle_mi_parser(self, data):
        nvme = {
            0 :     ["IC",                  bool((data[0] >> 7) & 0x1),   "Integrity Check"],
            1 :     ["MT",                  data[0] & 0x7F,               "Message Type"],
            2 :     ["ROR",                 bool((data[1]  >> 7) & 0x1),  "Request or Response"],
            3 :     ["NMIMT",               (data[1]  >> 3) & 0xF,        "NVMeMI Message type"],
            4 :     ["CSI",                 bool(data[1] & 0x1),          "Command Slot"],
            5 :     ["CIAP",                bool((data[2]  >> 1) & 0x1),  "Command Initiated Auto Pause"],
            6 :     ["MEB",                 bool(data[2] & 0x1),          "Management Endpoint Buffer"],
        }
        
        return nvme

    def handle_mi(self):
        Data = [self.packets[j][3] for j in range(8, 12)]
        nvme = self.handle_mi_parser(Data)
        self.ReqOrResp = nvme[2][1]
        
        msgType         = MCTP_MSG_TYPES.get(nvme[1][1], 'Reserved')
        self.msgMiType       = NVME_MI_MSG_TYPES.get(nvme[3][1], 'Reserved')
        
        self.put(self.packets[8][0], self.packets[11][1], self.out_ann, [3, 
        ['%s: %r | %s: %s | %s: %d | %s: %s | %s: %d | %s: %d | %s: %d' % (nvme[0][2], nvme[0][1], nvme[1][2], msgType, nvme[2][2], nvme[2][1], nvme[3][2], self.msgMiType, nvme[4][2], nvme[4][1], nvme[5][2], nvme[5][1], nvme[6][2], nvme[6][1]), 
        '%s %r | %s %02X | %s %d | %s %02X | %s %d | %s %d | %s %d' % (nvme[0][0], nvme[0][1], nvme[1][0], nvme[1][1], nvme[2][0], nvme[2][1], nvme[3][0], nvme[3][1], nvme[4][0], nvme[4][1], nvme[5][0], nvme[5][1], nvme[6][0], nvme[6][1]), 
        '%s | %s | %s | %s | %s | %s | %s' % (nvme[0][0], nvme[1][0], nvme[2][0], nvme[3][0], nvme[4][0], nvme[5][0], nvme[6][0]), 
        'Mi']])
        self.put(self.packets[8][0], self.packets[11][1], self.out_ann, [14, ['NVMe-MI Header', 'MI header', 'NMH']])
    
    def handle_mi_req_or_resp(self, data, firstPacket, Offset):
        if self.ReqOrResp == 0x1:
            status = self.packets[12][3]
            NVMeMiStatus = NVME_MI_STATUS.get(status, 'Reserveed')
            if status == 4:
                PEL  = self.packets[13][3] | (self.packets[14][3] << 8) | (self.packets[15][3] << 16)
                Bit = PEL & 0x7
                Byte = (PEL >> 8) & 0xFFFF
                self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [14, ['Status & PEL', 'Sta|PEL', 'S']])
                self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [3, 
                ['Status: %s | Parameter Error Location ► Byte: %d | Bit: %d' % (NVMeMiStatus, Byte, Bit), 
                'Status: %s | PEL ► B: %d | b: %d' % (NVMeMiStatus, Byte, Bit), 
                'Status: %02X | PEL: %06X' % (status, PEL), 
                '%02X | %06X' % (status, PEL), 
                'S']])
            elif status == 1:
                MPRT  = (self.packets[14][3] | (self.packets[15][3] << 8)) / 10
                self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [14, ['Status & MPRT', 'Sta|MPRT', 'S']])
                self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [3, 
                ['Status: %s | More Processing Required Time: %.1f s' % (NVMeMiStatus, MPRT), 
                'Status: %s | MPRT: %.1f s' % (NVMeMiStatus, MPRT), 
                'Status: %02X | MPRT: %.1f s' % (status, MPRT), 
                '%02X | %.1f s' % (status, MPRT), 
                'S']])
            elif status == 0:
                #self.handle_response_control_primitive()
                #self.handle_response_nvme_mi_command()
                #self.handle_response_nvme_admin_command()
                # s = 'handle_response_%s' % self.msgMiType.lower().replace(' ', '_')
                # handle_state = getattr(self, s)
                # handle_state()
                self.handle_mi_payload_response(data, firstPacket, Offset)
            else:
                self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [14, ['Status', 'Sta', 'S']])
                self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [3, 
                ['Status: %s' % NVMeMiStatus, 
                '%s' % NVMeMiStatus, 
                '%02X' % status, 
                'S']])
        else:
            self.handle_mi_payload_request(data, firstPacket, Offset)

    def handle_mi_payload_request(self, data, firstPacket, Offset):
        SizeData = len(data)
        # PayData = 0
        # for i in data:
            # PayData = (PayData << 8) | i
        
        # self.put(self.packets[firstPacket][0], self.packets[firstPacket + SizeData - 1][1], self.out_ann, [5, ['Payload Firstbyte = %d | Offset = %d | %X' % (firstPacket, Offset, SizeData), 'Pld %d | %d' % (firstPacket, Offset), 'S']])
        # NumPacket = 0
        # bits = 0
        # for i in range(firstPacket, (firstPacket + SizeData), 4):
            # bit1 = (i * 8)
            # bit2 = ((i + 4) * 8)
            # for bitoff in self.bytesXbits[bit1:bit2]:
                # bits = (bits << 1) | bitoff
            # dataPrint = [15, ['packet %d %d %d %08X %d' % (NumPacket, bit1, bit2, bits, 1), 'pckt %d' % NumPacket, '%d'%NumPacket]]
            # self.put(self.packets[i][0], self.packets[i+3][1], self.out_ann, dataPrint)
            # bits = 0
            # NumPacket += 1
        s = 'handle_request_%s' % self.msgMiType.lower().replace(' ', '_')
        handle_state = getattr(self, s)
        if s == 'handle_request_nvme_admin_command':
            handle_state(data, firstPacket, Offset)
        else:
            handle_state()
        
    def handle_mi_payload_response(self, data, firstPacket, Offset):
        SizeData = len(data)
        # self.put(self.packets[firstPacket][0], self.packets[firstPacket + SizeData - 1][1], self.out_ann, [5, ['Payload Firstbyte = %d | Offset = %d' % (firstPacket, Offset), 'Pld %d | %d' % (firstPacket, Offset), 'S']])
        # NumPacket = 0
        # bits = 0
        # for i in range(firstPacket, (firstPacket + SizeData), 4):
            # bit1 = (i * 8)
            # bit2 = ((i + 4) * 8)
            # for bitoff in self.bytesXbits[bit1:bit2]:
                # bits = (bits << 1) | bitoff
            # dataPrint = [15, ['packet %d %d %d %08X %d' % (NumPacket, bit1, bit2, bits, 1), 'pckt %d' % NumPacket, '%d'%NumPacket]]
            # self.put(self.packets[i][0], self.packets[i+3][1], self.out_ann, dataPrint)
            # bits = 0
            # NumPacket += 1
        #self.handle_response_control_primitive()
        # self.handle_response_nvme_mi_command()
        # self.handle_response_nvme_admin_command()
        s = 'handle_response_%s' % self.msgMiType.lower().replace(' ', '_')
        handle_state = getattr(self, s)
        if s == 'handle_response_nvme_admin_command' or 'handle_response_nvme_mi_command':
            handle_state(data, firstPacket, Offset)
        else:
            handle_state()

            
# ------------- Request Messages

    def handle_req_ctrl_prim_parser(self, data):
        ctrl_prim_req = {
            0 :     ["OPC",                 data[0],                      "Opcode"],
            1 :     ["TAG",                 data[1],                      "Tag"],
        }
        
        if ctrl_prim_req[0][1] == 0x03:
            ctrl_prim_req[2] = ["CESF",     bool(data[2] & 0x1),        "Clear Error State Flags"]
        elif ctrl_prim_req[0][1] == 0x04:
            ctrl_prim_req[2] = ["RRO",      data[2],                    "Response Replay Offset"]
        
        return ctrl_prim_req

    def handle_request_control_primitive(self):
        Data = [self.packets[j][3] for j in range(12, len(self.packets))]
        ctrl_prim = self.handle_req_ctrl_prim_parser(Data)
        CtrlPrim = NVME_CONTROL_OPCODES.get(ctrl_prim[0][1], 'Reserved')
        self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [14, ['Opcode', 'Opc', 'O']])
        
        self.LastOpcode = ctrl_prim[0][1]

    # "Get State",
        if ctrl_prim[0][1] == 0x03:
            self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [4, 
            ['Opcode: %s | TAG: %02X | Clear Error State Flags: %02X' % (CtrlPrim, ctrl_prim[1][1], ctrl_prim[2][1]), 
            'OPC: %s | TAG: %02X  | CESF: %02X' % (CtrlPrim, ctrl_prim[1][1], ctrl_prim[2][1]),
            'OPC: %02X | TAG: %02X | CESF: %d' % (ctrl_prim[0][1], ctrl_prim[1][1], ctrl_prim[2][1]), 
            'CPG']])
    # "Replay",
        elif ctrl_prim[0][1] == 0x04:
            self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [4, 
            ['Opcode: %s | TAG: %02X | Response Replay Offset: %02X' % (CtrlPrim, ctrl_prim[1][1], ctrl_prim[2][1]), 
            'OPC: %s | TAG: %02X  | RRO: %02X' % (CtrlPrim, ctrl_prim[1][1], ctrl_prim[2][1]), 
            'OPC: %02X | TAG: %02X | RRO: %02X' % (ctrl_prim[0][1], ctrl_prim[1][1], ctrl_prim[2][1]), 
            'CPRY']])
    # "Pause", "Resume", "Abort",
        elif ctrl_prim[0][1] < 0x03:
            self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [4, 
            ['Opcode: %s | TAG: %02X' % (CtrlPrim, ctrl_prim[1][1]), 
            'OPC: %s | TAG: %02X' % (CtrlPrim, ctrl_prim[1][1]), 
            'Opc: %02X | TAG: %02X' % (ctrl_prim[0][1], ctrl_prim[1][1]), 
            'CP']])            

    def handle_req_nvme_mi_parser(self, data):
        nvme_mi_req = {
            0 :                 ["OPC",                     data[0],                                    "Opcode"],
        }
    # "Read NVMe-MI Data Structure",
        if nvme_mi_req[0][1] == 0x00:
            # DWORD 0 (bytes: 16 - 19)
            nvme_mi_req[1] = ["CTRLID",                     data[4] | (data[5] << 8),                   "Data Structure Type"]
            nvme_mi_req[2] = ["PORTID",                     data[6],                                    "Port Identifier"]
            nvme_mi_req[3] = ["DTYP",                       data[7],                                    "Controller Identifier"]
            # DWORD 1 (Bytes: 20 - 23)                  
            nvme_mi_req[4] = ["IOCSI",                      data[8],                                    "I/O Command Set Identifier"]
    # "NVM Subsystem Health Status Poll",
        elif nvme_mi_req[0][1] == 0x01:
            # DWORD 0 (Bytes: 16 - 19) Reserved
            # DWORD 1 (Bytes: 20 - 23)
            nvme_mi_req[1] = ["CS",                         bool(data[11] & 0x80),                      "Clear Status"]
    # "Controller Health Status Poll",
        elif nvme_mi_req[0][1] == 0x02:
            # DWORD 0 (Bytes: 16 - 19)
            byte_DW0_4 = data[7]
            nvme_mi_req[1] = ["SCTILD",                     data[4] | (data[5]  << 8),                  "Starting Controller ID"]
            nvme_mi_req[2] = ["MaxRent",                    data[6],                                    "Maximum Response Entries"]
            nvme_mi_req[3] = ["ALL",                        bool((byte_DW0_4 >> 7) & 0x1),              "Report All"]
            nvme_mi_req[4] = ["INCVF",                      bool((byte_DW0_4 >> 2) & 0x1),              "Include SR-IOV Virtual Functions"]
            nvme_mi_req[5] = ["INCPF",                      bool((byte_DW0_4 >> 1) & 0x1),              "Include SR-IOV Physical Functions"]
            nvme_mi_req[6] = ["INCF",                       bool(byte_DW0_4 & 0x1),                     "Include PCI Functions"]

            # DWORD 1 (Bytes: 20 - 23)
            nvme_mi_req[7] = ["CWAR",                       bool((data[8] >> 4) & 0x1),                 "Critical Warning"]
            nvme_mi_req[8] = ["SPARE",                      bool((data[8] >> 3) & 0x1),                 "Available Spare"]
            nvme_mi_req[9] = ["PDLU",                       bool((data[8] >> 2) & 0x1),                 "Percentage Used"]
            nvme_mi_req[10] = ["CTEM",                      bool((data[8] >> 1) & 0x1),                 "Composite Temperature Changes"]
            nvme_mi_req[11] = ["CSTS",                      bool(data[8] & 0x1),                        "Controller Status Changes"]
            nvme_mi_req[12] = ["CCF",                       bool((data[11] >> 7) & 0x1),                "Clear Changed Flags"]
    # "Configuration Set",
        elif nvme_mi_req[0][1] == 0x03:
            # DWORD 0 (Bytes: 16 - 19)
            nvme_mi_req[1] = ["CID",                        data[4],                                    "Configuration Identifier"]
            if nvme_mi_req[1][1] == 0x01:
                # DWORD 1 (Bytes: 20 - 23) Reserved
                nvme_mi_req[2] = ["SFREQ",                  data[5] & 0x0F,                             "SMBus/I2C Frequency"]
                nvme_mi_req[3] = ["PORTID",                 data[7],                                    "Port Identifier"]
            elif nvme_mi_req[1][1] == 0x02:
                # DWORD 1 (Bytes: 20 - 23)
                byte_DW1_0 = data[8]
                byte_DW1_1 = data[9]

                nvme_mi_req[2] = ["CSCHNG",                  bool(byte_DW1_0 & 0x80),                    "Controller Status Change"]
                nvme_mi_req[3] = ["FA",                      bool(byte_DW1_0 & 0x40),                    "Firmware Activated"]
                nvme_mi_req[4] = ["NAC",                     bool(byte_DW1_0 & 0x20),                    "Namespace Attribute Changed"]
                nvme_mi_req[5] = ["CECO",                    bool(byte_DW1_0 & 0x10),                    "Controller Enable Change Occurred"]
                nvme_mi_req[6] = ["NSSRO",                   bool(byte_DW1_0 & 0x08),                    "NVM Subsystem Reset Occurred"]
                nvme_mi_req[7] = ["SHST",                    bool(byte_DW1_0 & 0x04),                    "Shutdown Status"]
                nvme_mi_req[8] = ["CFS",                     bool(byte_DW1_0 & 0x02),                    "Controller Fatal Status"]
                nvme_mi_req[9] = ["RDY",                     bool(byte_DW1_0 & 0x01),                    "Ready"]
                                    
                nvme_mi_req[10] = ["TCIDA",                  bool(byte_DW1_1 & 0x10),                    "Telemetry Controller-Initiated Data Available"]
                nvme_mi_req[11] = ["CWARN",                  bool(byte_DW1_1 & 0x08),                    "Critical Warning"]
                nvme_mi_req[12] = ["SPARE",                  bool(byte_DW1_1 & 0x04),                    "Available Spare"]
                nvme_mi_req[13] = ["PDLU",                   bool(byte_DW1_1 & 0x02),                    "Percentage Used"]
                nvme_mi_req[14] = ["CTEMP",                  bool(byte_DW1_1 & 0x01),                    "Composite Temperature"]
            elif nvme_mi_req[1][1] == 0x03:
                # DWORD 0 (Bytes: 16 - 19)
                nvme_mi_req[2] = ["PORTID",                 data[7],                                    "Port Identifier"]
                # DWORD 1 (Bytes: 20 - 23)
                nvme_mi_req[3] = ["MTUS",                   data[8] | (data[9]  << 8),                  "MCTP Transmission Unit Size"]
            elif nvme_mi_req[1][1] == 0x04:
                # DWORD 0 (Bytes: 16 - 19) / DWORD 1 (Bytes: 20 - 23) Reserved
                nvme_mi_req[2] = ["AERD",                   data[5],                                    "AEM Retry Delay"]
                nvme_mi_req[3] = ["AEMD",                   data[6],                                    "AEM Delay"]
                nvme_mi_req[4] = ["ENVFA",                  bool(data[7] & 0x04),                       "Enable SR-IOV Virtual Functions AE"]
                nvme_mi_req[5] = ["ENPFA",                  bool(data[7] & 0x02),                       "Enable SR-IOV Physical Functions AE"]
                nvme_mi_req[6] = ["ENCFA",                  bool(data[7] & 0x01),                       "Enable PCI Functions AE"]
                
                if len(data) > 17:
                    # Request Data                
                    nvme_mi_req[7] = ["NUMAEE",                 data[12],                                   "Number of AE Enable Data Structures"]
                    nvme_mi_req[8] = ["AEELVER",                data[13],                                   "AE Enable List Version Number"]
                    nvme_mi_req[9] = ["AEETL",                  data[14] | (data[15] << 8),                 "AE Enable Total Length"]
                    nvme_mi_req[10] = ["AEELHL",                data[16],                                   "AE Enable List Header Length"]
                    j = 17
                    k = 11
                    for i in range(0, nvme_mi_req[7][1]):
                        nvme_mi_req[k] = ["AEE%d" % i,          data[j]|(data[j+1] << 8)|(data[j+2] << 16), "AE Enable Data %d" % i]
                        nvme_mi_req[k + 1] = ["AEEL",           data[j],                                    "       AE Enable Length"]
                        nvme_mi_req[k + 2] = ["AEEI",           data[j + 1],                                "       AE Enable ID"]
                        nvme_mi_req[k + 3] = ["AEE",            bool(data[j + 2] & 0x80),                   "       AE Enable"]
                        j += 3
                        k += 4
    # "Configuration Get",
        elif nvme_mi_req[0][1] == 0x04:
            # DWORD 0 (Bytes: 16 - 19) / DWORD 1 (Bytes: 20 - 23) Reserved
            nvme_mi_req[1] = ["CID",                        data[4],                                    "Configuration Identifier"]
            if nvme_mi_req[1][1] == 0x01 or nvme_mi_req[1][1] == 0x03:
                nvme_mi_req[2] = ["PORTID",                     data[7],                                    "Port Identifier"]
    # "VPD Read",
        elif nvme_mi_req[0][1] == 0x05:
            # DWORD 0 (Bytes: 16 - 19)
            nvme_mi_req[1] = ["DOFST",                      data[4] | (data[5] << 8),                   "Data Offset"]
            # DWORD 1 (Bytes: 20 - 23)
            nvme_mi_req[2] = ["DLEN",                       data[8] | (data[9] << 8),                   "Data Length"]
    # "VPD Write",
        elif nvme_mi_req[0][1] == 0x06:
            # DWORD 0 (Bytes: 16 - 19)
            nvme_mi_req[1] = ["DOFST",                      data[4] | (data[5] << 8),                   "Data Offset"]
            # DWORD 1 (Bytes: 20 - 23)
            nvme_mi_req[2] = ["DLEN",                       data[8] | (data[9] << 8),                   "Data Length"]
            # Request Data 
            nvme_mi_req[3] = ["WRD",                        0,                                          "VPD Data"]
            for i in data[12:-5]:
                nvme_mi_req[3][1] = data[i] | (nvme_mi_req[3][1] << 8)
    # "Reset",
        elif nvme_mi_req[0][1] == 0x07:
            # DWORD 0 (Bytes: 16 - 19) / DWORD 1 (Bytes: 20 - 23) Reserved
            nvme_mi_req[1] = ["RSTTYP",                     data[7],                                    "Reset Type"]
    # "SES Receive",
        elif nvme_mi_req[0][1] == 0x08:
            # DWORD 0 (Bytes: 16 - 19)
            nvme_mi_req[1] = ["PCODE",                      data[4],                                    "Page Code"]
            # DWORD 1 (Bytes: 20 - 23)
            nvme_mi_req[2] = ["ALENGTH",                    data[8] | (data[9] << 8),                   "Allocation Length"]
    # "SES Send",
        elif nvme_mi_req[0][1] == 0x09:
            # DWORD 0 (Bytes: 16 - 19) Reserved / DWORD 1 (Bytes: 20 - 23)
            nvme_mi_req[1] = ["DLEN",                       data[8] | (data[9] << 8),                   "Data Length"]
            # Request Data 
            nvme_mi_req[2] = ["SRD",                        0,                                          "SES Data"]
            for i in data[12:-5]:
                nvme_mi_req[2][1] = data[i] | (nvme_mi_req[2][1] << 8)
    # "MEB Read",
        elif nvme_mi_req[0][1] == 0x0A:
            # DWORD 0 (Bytes: 16 - 19)
            nvme_mi_req[1] = ["DOFST",                      data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24),"Data Offset"]
            # DWORD 1 (Bytes: 20 - 23)
            nvme_mi_req[2] = ["DLEN",                       data[8] | (data[9] << 8),                   "Data Length"]
    # "MEB Write",
        elif nvme_mi_req[0][1] == 0x0B:
            # DWORD 0 (Bytes: 16 - 19)
            nvme_mi_req[1] = ["DOFST",                      data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24),"Data Offset"]
            # DWORD 1 (Bytes: 20 - 23)
            nvme_mi_req[2] = ["DLEN",                       data[8] | (data[9] << 8),                   "Data Length"]
            # Request Data 
            nvme_mi_req[3] = ["WRD",                        0,                                          "MEB Data"]
            for i in data[12:-5]:
                nvme_mi_req[3][1] = data[i] | (nvme_mi_req[3][1] << 8)
    # "Shutdown",
        elif nvme_mi_req[0][1] == 0x0C:
            # DWORD 0 (Bytes: 16 - 19) / DWORD 1 (Bytes: 20 - 23) reserved
            nvme_mi_req[1] = ["SHDNTYP",                    data[7],                                    "Shutdown Type"]
    #  "Vendor Specific"
        elif nvme_mi_req[0][1] > 0x0C:
            # DWORD 0 (Bytes: 16 - 19)
            # DWORD 1 (Bytes: 20 - 23)
            return
        return nvme_mi_req

    def handle_request_nvme_mi_command(self):
        Data = [self.packets[j][3] for j in range(12, len(self.packets))]
        nvme_mi_req = self.handle_req_nvme_mi_parser(Data)
        NVMe_Mi = NVME_MI_OPCODES.get(nvme_mi_req[0][1], "Reserved")
        
        self.LastOpcode = nvme_mi_req[0][1]

        self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [3, 
        ["NVMe MI command: %s" % NVMe_Mi, 
        'MI command: %s' % NVMe_Mi, 
        'Opc: %02X' % nvme_mi_req[0][1], 
        'opc']])

        self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [14, ['Opcode', 'Opc', 'O']])
        self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [14, ['DWORD 0', 'DW 0', 'D0']])
        self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [14, ['DWORD 1', 'DW 1', 'D1']])
    # "Read NVMe-MI Data Structure",
        if nvme_mi_req[0][1] == 0x00:
            self.LastDytp = nvme_mi_req[3][1]
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['%s: %04X | %s: %02X | %s: %02X' % 
            (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1]), 
            '%s: %04X | %s: %02X | %s: %02X' % 
            (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1]), 
            '%s | %s | %s' %
            (nvme_mi_req[1][0], nvme_mi_req[2][0], nvme_mi_req[3][0]), 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['%s: %02X' % (nvme_mi_req[4][2], nvme_mi_req[4][1]), 
            '%s: %02X' % (nvme_mi_req[4][0], nvme_mi_req[4][1]),
            '%s' % nvme_mi_req[4][0], 
            'DW1']])
    # "NVM Subsystem Health Status Poll",
        elif nvme_mi_req[0][1] == 0x01:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['Reserved: 00 00 00 00', 
            'RSVD: 00 00 00 00', 
            'RSVD', 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['%s: %r' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %r' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW1']])
    # "Controller Health Status Poll",
        elif nvme_mi_req[0][1] == 0x02:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [3, 
            ['%s: %04X | %s: %02X | %s: %r | %s: %r | %s: %r | %s: %r' %
            (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1], nvme_mi_req[4][2], nvme_mi_req[4][1], nvme_mi_req[5][2], nvme_mi_req[5][1], nvme_mi_req[6][2], nvme_mi_req[6][1]), 
            '%s: %04X | %s: %02X | %s: %r | %s: %r | %s: %r | %s: %r' %
            (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1], nvme_mi_req[4][0], nvme_mi_req[4][1], nvme_mi_req[5][0], nvme_mi_req[5][1], nvme_mi_req[6][0], nvme_mi_req[6][1]), 
            '%s | %s | %s | %s | %s | %s' %
            (nvme_mi_req[1][0], nvme_mi_req[2][0], nvme_mi_req[3][0], nvme_mi_req[4][0], nvme_mi_req[5][0], nvme_mi_req[6][0]), 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [3, 
            ['%s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r' %
            (nvme_mi_req[7][2], nvme_mi_req[7][1], nvme_mi_req[8][2], nvme_mi_req[8][1], nvme_mi_req[9][2], nvme_mi_req[9][1], nvme_mi_req[10][2], nvme_mi_req[10][1], nvme_mi_req[11][2], nvme_mi_req[11][1], nvme_mi_req[12][2], nvme_mi_req[12][1]), 
            '%s: %04X | %s: %02X | %s: %r | %s: %r | %s: %r | %s: %r' %
            (nvme_mi_req[7][0], nvme_mi_req[7][1], nvme_mi_req[8][0], nvme_mi_req[8][1], nvme_mi_req[9][0], nvme_mi_req[9][1], nvme_mi_req[10][0], nvme_mi_req[10][1], nvme_mi_req[11][0], nvme_mi_req[11][1], nvme_mi_req[12][0], nvme_mi_req[12][1]), 
            '%s | %s | %s | %s | %s | %s' %
            (nvme_mi_req[7][0], nvme_mi_req[8][0], nvme_mi_req[9][0], nvme_mi_req[10][0], nvme_mi_req[11][0], nvme_mi_req[12][0]), 
            'DW0']])
    # "Configuration Set",
        elif nvme_mi_req[0][1] == 0x03:
            self.LastCID = nvme_mi_req[1][1]
            if nvme_mi_req[1][1] == 0x01:
                self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
                ['%s: %02X | %s: %02X | %s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1]), 
                '%s: %02X | %s: %02X | %s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1]), 
                '%s | %s | %s' % (nvme_mi_req[1][0], nvme_mi_req[2][0], nvme_mi_req[3][0]), 
                'DW0']])
                
                self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
                ['Reserved: 00 00 00 00', 
                'RSVD: 00 00 00 00', 
                'RSVD', 
                'DW1']])
            elif nvme_mi_req[1][1] == 0x02:
                self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
                ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
                '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
                '%s' % nvme_mi_req[1][0], 
                'DW0']])

                self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [3, 
                ['%s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d' % 
                (nvme_mi_req[10][2], nvme_mi_req[10][1], nvme_mi_req[11][2], nvme_mi_req[11][1], nvme_mi_req[12][2], nvme_mi_req[12][1], nvme_mi_req[13][2], nvme_mi_req[13][1], nvme_mi_req[14][2], nvme_mi_req[14][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1], nvme_mi_req[4][2], nvme_mi_req[4][1], nvme_mi_req[5][2], nvme_mi_req[5][1], nvme_mi_req[6][2], nvme_mi_req[6][1], nvme_mi_req[7][2], nvme_mi_req[7][1], nvme_mi_req[8][2], nvme_mi_req[8][1], nvme_mi_req[9][2], nvme_mi_req[9][1]),
                '%s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d' % 
                (nvme_mi_req[10][0], nvme_mi_req[10][1], nvme_mi_req[11][0], nvme_mi_req[11][1], nvme_mi_req[12][0], nvme_mi_req[12][1], nvme_mi_req[13][0], nvme_mi_req[13][1], nvme_mi_req[14][0], nvme_mi_req[14][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1], nvme_mi_req[4][0], nvme_mi_req[4][1], nvme_mi_req[5][0], nvme_mi_req[5][1], nvme_mi_req[6][0], nvme_mi_req[6][1], nvme_mi_req[7][0], nvme_mi_req[7][1], nvme_mi_req[8][0], nvme_mi_req[8][1], nvme_mi_req[9][0], nvme_mi_req[9][1]),
                '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' % 
                (nvme_mi_req[10][0], nvme_mi_req[11][0], nvme_mi_req[12][0], nvme_mi_req[13][0], nvme_mi_req[14][0], nvme_mi_req[2][0], nvme_mi_req[3][0], nvme_mi_req[4][0], nvme_mi_req[5][0], nvme_mi_req[6][0], nvme_mi_req[7][0], nvme_mi_req[8][0], nvme_mi_req[9][0]),
                'bits (12 - 0) %d %d %d %d %d %d %d %d %d %d %d %d %d' % 
                (nvme_mi_req[10][1], nvme_mi_req[11][1], nvme_mi_req[12][1], nvme_mi_req[13][1], nvme_mi_req[14][1], nvme_mi_req[2][1], nvme_mi_req[3][1], nvme_mi_req[4][1], nvme_mi_req[5][1], nvme_mi_req[6][1], nvme_mi_req[7][1], nvme_mi_req[8][1], nvme_mi_req[9][1]),
                'DW1']])
            elif nvme_mi_req[1][1] == 0x03:
                self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
                ['%s: %02X | %s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1]), 
                '%s: %02X | %s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1]), 
                '%s | %s' % (nvme_mi_req[1][0], nvme_mi_req[2][0]), 
                'DW0']])

                self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
                ['%s: %04X' % (nvme_mi_req[3][2], nvme_mi_req[3][1]), 
                '%s: %04X' % (nvme_mi_req[3][0], nvme_mi_req[3][1]),
                '%s' % nvme_mi_req[3][0], 
                'DW1']])
            elif nvme_mi_req[1][1] == 0x04:
                self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
                ['%s: %02X | Async Event ► %s: %02X → %s: %02X → %s: %r → %s: %r → %s: %r' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1], nvme_mi_req[4][2], nvme_mi_req[4][1], nvme_mi_req[5][2], nvme_mi_req[5][1], nvme_mi_req[6][2], nvme_mi_req[6][1]), 
                '%s: %02X | %s: %02X → %s: %02X → %s: %r → %s: %r → %s: %r' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1], nvme_mi_req[4][0], nvme_mi_req[4][1], nvme_mi_req[5][0], nvme_mi_req[5][1], nvme_mi_req[6][0], nvme_mi_req[6][1]), 
                '%s | %s → %s → %s → %s → %s' % (nvme_mi_req[1][0], nvme_mi_req[2][0], nvme_mi_req[3][0], nvme_mi_req[4][0], nvme_mi_req[5][0], nvme_mi_req[6][0]), 
                'DW0']])
                
                self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
                ['Reserved: 00 00 00 00', 
                'RSVD: 00 00 00 00', 
                '00 00 00 00', 
                'DW1']])
                if len(Data) > 17:
                    # Request Data                
                    self.put(self.packets[24][0], self.packets[27][1], self.out_ann, [14, ['AE Enable List Header', 'AE List', 'AE']])
                    self.put(self.packets[24][0], self.packets[27][1], self.out_ann, [4, 
                    ['%s: %02X | %s: %02X | %s: %04X' % (nvme_mi_req[7][2], nvme_mi_req[7][1], nvme_mi_req[8][2], nvme_mi_req[8][1], nvme_mi_req[9][2], nvme_mi_req[9][1]), 
                    '%s: %02X | %s: %02X | %s: %04X' % (nvme_mi_req[7][0], nvme_mi_req[7][1], nvme_mi_req[8][0], nvme_mi_req[8][1], nvme_mi_req[9][0], nvme_mi_req[9][1]), 
                    '%s | %s | %s' % (nvme_mi_req[7][0], nvme_mi_req[8][0], nvme_mi_req[9][0]), 
                    'AE']])
                    self.put(self.packets[28][0], self.packets[28][1], self.out_ann, [14, ['AE Enable List Header', 'AE List', 'AE']])
                    self.put(self.packets[28][0], self.packets[28][1], self.out_ann, [4, 
                    ['%s: %02X' % (nvme_mi_req[10][2], nvme_mi_req[10][1]), 
                    '%s: %02X' % (nvme_mi_req[10][0], nvme_mi_req[10][1]), 
                    '%s' % (nvme_mi_req[10][0]), 
                    'AE']])
                
                    j = 29
                    k = 11
                    for i in range(0, nvme_mi_req[7][1]):
                        self.put(self.packets[j][0], self.packets[j+2][1], self.out_ann, [14, ['AE Enable Data Structure %d' % i, 'AE Ena DS %d' % i, 'AE%d' % i]])
                        self.put(self.packets[j][0], self.packets[j+2][1], self.out_ann, [4, 
                        ['%s ► %s: %02X → %s: %02X → %s: %r' % (nvme_mi_req[k][2], nvme_mi_req[k + 1][2], nvme_mi_req[k + 1][1], nvme_mi_req[k + 2][2], nvme_mi_req[k + 2][1], nvme_mi_req[k + 3][2], nvme_mi_req[k + 3][1]), 
                        '%s ► %s: %02X → %s: %02X → %s: %r' % (nvme_mi_req[k][0], nvme_mi_req[k + 1][0], nvme_mi_req[k + 1][1], nvme_mi_req[k + 2][0], nvme_mi_req[k + 2][1], nvme_mi_req[k + 3][0], nvme_mi_req[k + 3][1]), 
                        '%s ► %s → %s → %s' % (nvme_mi_req[k][0], nvme_mi_req[k + 1][0], nvme_mi_req[k + 2][0], nvme_mi_req[k + 3][0]), 
                        'DS']])
                        j += 3
                        k += 4
    # "Configuration Get",
        elif nvme_mi_req[0][1] == 0x04:
            self.LastCID = nvme_mi_req[1][1]
            if nvme_mi_req[1][1] == 0x01 or nvme_mi_req[1][1] == 0x03:
                self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
                ['%s: %02X | %s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1]), 
                '%s: %02X | %s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1]), 
                '%s | %s' %(nvme_mi_req[1][0], nvme_mi_req[2][0]), 
                'DW0']])
            else:
                self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
                ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
                '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
                '%s' % nvme_mi_req[1][0], 
                'DW0']])
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['Reserved: 00 00 00 00', 
            'RSVD: 00 00 00 00', 
            '00 00 00 00', 
            'DW1']])
    # "VPD Read",
        elif nvme_mi_req[0][1] == 0x05:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['%s: %04X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %04X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), 
            '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),
            '%s' % nvme_mi_req[2][0], 
            'DW1']])
    # "VPD Write",
        elif nvme_mi_req[0][1] == 0x06:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['%s: %04X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %04X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), 
            '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),
            '%s' % nvme_mi_req[2][0], 
            'DW1']])
            
            self.put(self.packets[24][0], self.packets[-6][1], self.out_ann, [14, ['Request Data', 'Req Data', 'RQ']])
            self.put(self.packets[24][0], self.packets[-6][1], self.out_ann, [4, 
            ['%s: %X' % (nvme_mi_req[3][2], nvme_mi_req[3][1]), 
            '%s: %X' % (nvme_mi_req[3][0], nvme_mi_req[3][1]), 
            '%s' % nvme_mi_req[3][0], 
            'RD']])
    # "Reset",
        elif nvme_mi_req[0][1] == 0x07:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['Reserved: 00 00 00 00', 
            'RSVD: 00 00 00 00', 
            'RSVD', 
            'DW1']])
    # "SES Receive",
        elif nvme_mi_req[0][1] == 0x08:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), 
            '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),
            '%s' % nvme_mi_req[2][0], 
            'DW1']])
    # "SES Send",
        elif nvme_mi_req[0][1] == 0x09:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['Reserved: 00 00 00 00', 
            'RSVD: 00 00 00 00', 
            'RSVD', 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW1']])
            
            self.put(self.packets[24][0], self.packets[-6][1], self.out_ann, [14, ['Request Data', 'Req Data', 'RQ']])
            self.put(self.packets[24][0], self.packets[-6][1], self.out_ann, [4, 
            ['%s: %X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), 
            '%s: %X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),
            '%s' % nvme_mi_req[2][0], 
            'RQ']])
    # "MEB Read",
        elif nvme_mi_req[0][1] == 0x0A:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['%s: %08X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %08X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), 
            '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),
            '%s' % nvme_mi_req[2][0], 
            'DW1']])
    # "MEB Write",
        elif nvme_mi_req[0][1] == 0x0B:  
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['%s: %08X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %08X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), 
            '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),
            '%s' % nvme_mi_req[2][0], 
            'DW1']])

            self.put(self.packets[24][0], self.packets[-6][1], self.out_ann, [14, ['Request Data', 'Req Data', 'RQ']])
            self.put(self.packets[24][0], self.packets[-6][1], self.out_ann, [4, 
            ['%s: %X' % (nvme_mi_req[3][2], nvme_mi_req[3][1]), 
            '%s: %X' % (nvme_mi_req[3][0], nvme_mi_req[3][1]), 
            '%s' % nvme_mi_req[3][0], 
            'RD']])
    # "Shutdown",
        elif nvme_mi_req[0][1] == 0x0C:
            self.put(self.packets[16][0], self.packets[19][1], self.out_ann, [4, 
            ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), 
            '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),
            '%s' % nvme_mi_req[1][0], 
            'DW0']])
            
            self.put(self.packets[20][0], self.packets[23][1], self.out_ann, [4, 
            ['Reserved: 00 00 00 00', 
            'RSVD: 00 00 00 00', 
            'RSVD', 
            'DW1']])
    #  "Vendor Specific"
        elif nvme_mi_req[0][1] > 0x0C:
            # DWORD 0 (Bytes: 16 - 19)
            # DWORD 1 (Bytes: 20 - 23)
            return
        
    def handle_req_nvme_admin_parser(self, data, Offset, Len):
        admin_req = {
            0 :            ["OPC",                     data[0],                                                                     "Opcode"],
            1 :            ["CFLGS",                   data[1],                                                                     "Command Flags"],
            2 :            ["ISH",                     bool((data[1] >> 2) & 0x01),                                                 "       Ignore Shutdown"],
            3 :            ["DOFSTV",                  bool((data[1] >> 1) & 0x01),                                                 "       DOFST Valid"],
            4 :            ["DLENV",                   bool(data[1] & 0x01),                                                        "       DLEN Valid"],
            5 :            ["CTLID",                   data[2] | (data[3] << 8),                                                    "Controller ID"],
            6 :            ["NSID",                    data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24),                "Namespace"],     # SQE DW 1
            7 :            ["DW2",                     data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24),              "DWORD 2"],   # SQE DW 2
            8 :            ["DW3",                     data[12] | (data[13] << 8) | (data[14] << 16) | (data[15] << 24),            "DOWRD 3"], # SQE DW 3
            9 :            ["MPTRL",                   data[16] | (data[17] << 8) | (data[18] << 16) | (data[19] << 24),            "Metadata Pointer MPTR Low"], # SQE DW 4
            10 :           ["MPTRU",                   data[20] | (data[21] << 8) | (data[22] << 16) | (data[23] << 24),            "Metadata Pointer MPTR Upper"], # SQE DW 5
            11 :           ["DOFST",                   data[24] | (data[25] << 8) | (data[26] << 16) | (data[27] << 24),            "Data Offset"], # DOFST
            12 :           ["DLEN",                    data[28] | (data[29] << 8) | (data[30] << 16) | (data[31] << 24),            "Data Length"], # DLEN
        }

        DW10    = data[40] | (data[41] << 8) | (data[42] << 16) | (data[43] << 24)  # SQE DW 10
        DW11    = data[44] | (data[45] << 8) | (data[46] << 16) | (data[47] << 24)  # SQE DW 11
        DW12    = data[48] | (data[49] << 8) | (data[50] << 16) | (data[51] << 24)  # SQE DW 12
        DW13    = data[52] | (data[53] << 8) | (data[54] << 16) | (data[55] << 24)  # SQE DW 13
        DW14    = data[56] | (data[57] << 8) | (data[58] << 16) | (data[59] << 24)  # SQE DW 14
        DW15    = data[60] | (data[61] << 8) | (data[62] << 16) | (data[63] << 24)  # SQE DW 15

        if (admin_req[0][1] == 0x00 and self.LastOpcode == 0x02) or (admin_req[0][1] == 0x02):      # "Get Log Page",
            # SQE DW 10
            admin_req[13] =  ["NUMDL",                   (DW10 >> 16) & 0xFFFF,                                                      "Number of Dwords Lower"]
            admin_req[14] =  ["RAE",                     bool((DW10 >> 15) & 0x1),                                                   "Retain Asynchronous Event"]
            admin_req[15] =  ["LSP",                     (DW10 >> 8) & 0x7F,                                                         "Log Specific Parameter"]
            admin_req[16] =  ["LID",                     DW10 & 0xFF,                                                                "Log Page Identifier"]
            # SQE DW 11     
            admin_req[17] =  ["LSI",                     (DW11 >> 16) & 0xFFFF,                                                      "Log Specific Identifier"]
            admin_req[18] =  ["NUMDU",                   DW11 & 0xFFFF,                                                              "Number of Dwords"]
            # SQE DW 12     
            admin_req[19] =  ["LPOL",                    DW12,                                                                       "Log Page Offset Lower"]
            # SQE DW 13     
            admin_req[20] =  ["LPOU",                    DW13,                                                                       "Log Page Offset Upper"]
            # SQE DW 14     
            admin_req[21] =  ["CSI",                     (DW14 >> 24) & 0xFF,                                                        "Command Set Identifier"]
            admin_req[22] =  ["OT",                      bool((DW14 >> 23) & 0x1),                                                   "Offset Type"]
            admin_req[23] =  ["UIDX",                    DW14 & 0x7F,                                                                "UUID Index"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x06) or (admin_req[0][1] == 0x06):    # "Identify",
            # SQE DW 10
            admin_req[13] =  ["CNS",                     DW10 & 0xFF,                                                                "Controller or Namespace Structure"]            
            admin_req[14] =  ["CNTID",                   (DW10 >> 16) & 0xFFFF,                                                      "Controller Identifier"]
            # SQE DW 11
            admin_req[15] =  ["CNSSID",                  DW11 & 0xFFFF,                                                      "CNS Specific Identifier"]
            admin_req[16] =  ["CSI",                     (DW11 >> 24) & 0xFF,                                                        "Command Set Identifier"]
            # SQE DW 12
            # SQE DW 13
            # SQE DW 14
            admin_req[17] =  ["UIDX",                    DW14 & 0x7F,                                                                "UUID Index"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x09) or (admin_req[0][1] == 0x09):    # "Set Features",
            # SQE DW 10
            admin_req[13] =  ["FID",                     DW10 & 0xFF,                                                                "Feature Identifier"]            
            admin_req[14] =  ["SV",                      bool((DW10 >> 31) & 0x01),                                                  "Save"]            
            # SQE DW 11
            # SQE DW 12
            # SQE DW 13
            # SQE DW 14
            admin_req[15] =  ["UIDX",                    DW14 & 0x7F,                                                                "UUID Index"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x0A) or (admin_req[0][1] == 0x0A):    # "Get Features",
            # SQE DW 10
            admin_req[13] =  ["FID",                     DW10 & 0xFF,                                                                "Feature Identifier"]            
            admin_req[14] =  ["SEL",                     ((DW10 >> 8) & 0x07),                                                         "Select"]            
            # SQE DW 11
            # SQE DW 12
            # SQE DW 13
            # SQE DW 14
            admin_req[15] =  ["UIDX",                    DW14 & 0x7F,                                                                "UUID Index"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x0D) or (admin_req[0][1] == 0x0D):    # "Namespace Management",
            # SQE DW 10
            admin_req[13] =  ["SEL",                     (DW10 & 0x0F),                                                         "Select"]            
            # SQE DW 11
            admin_req[14] =  ["CSI",                     (DW11 >> 24) & 0xFF,                                                        "Command Set Identifier"]
            # SQE DW 12
            # SQE DW 13
            # SQE DW 14
            # SQE DW 15
            admin_req[15] =  ["SIOCS",                     0,                                                                        "Specific to the I/O Command Set"]
            for i in data[64:575]:
                admin_req[15][1] = data[i] | (admin_req[15][1] << 8)
            admin_req[16] =  ["VS",                     0,                                                                           "Vendor Specific"]
            for i in data[1088:4159]:
                admin_req[16][1] = data[i] | (admin_req[16][1] << 8)
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x10) or (admin_req[0][1] == 0x10):    # "Firmware Commit",
            # SQE DW 10
            admin_req[13] =  ["FS",                     (DW10 & 0x07),                                                               "Firmware Slot"]            
            admin_req[14] =  ["CA",                      (DW10 >> 3) & 0x07,                                                        "Commit Action"]            
            admin_req[15] =  ["BPID",                    bool((DW10 >> 31) & 0x01),                                                   "Boot Partition ID"]            
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x11) or (admin_req[0][1] == 0x11):    # "Firmware Image Download",
            # SQE DW 10
            admin_req[13] = ["NUMD",                     DW10,                                                                       "Number of Dwords"]
            # SQE DW 11
            admin_req[14] = ["OFST",                     DW11,                                                                       "Offset"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x14) or (admin_req[0][1] == 0x14):    # "Device Self-Test",
            # SQE DW 10
            admin_req[13] = ["STC",                     (DW10 & 0x0F),                                                                       "Self-test Code"]
            # SQE DW 11
            # SQE DW 12
            # SQE DW 13
            # SQE DW 14
            # SQE DW 15
            admin_req[14] = ["DSTP",                     DW10,                                                                       "Device Self-test Parameter"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x15) or (admin_req[0][1] == 0x15):    # "Namespace attachment",
            # SQE DW 10
            admin_req[1] = ["SEL",                     (DW10 & 0xF),                                                                       "Select"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x1C) or (admin_req[0][1] == 0x1C):    # "Virtualization Management",
            # SQE DW 10
            admin_req[13] = ["ACT",                     (DW10 & 0xF),                                                                       "Action"]
            admin_req[14] = ["RT",                     (DW10 >> 8) & 0x7,                                                                       "Resource Type"]
            admin_req[15] = ["CNTLID",                     (DW10 >> 16) & 0xFFFF,                                                                       "Controller Identifier"]
            # SQE DW 11
            admin_req[16] = ["NR",                     (DW11 & 0xFFFF),                                                                       "Number of Controller Resources"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x20) or (admin_req[0][1] == 0x20):    # "Capacity Management",
            # SQE DW 10
            admin_req[13] = ["OPER",                     (DW10 & 0xF),                                                                       "Operation"]
            admin_req[14] = ["ELID",                     (DW10 >> 16) & 0xFFFF,                                                                       "Element Identifier"]
            # SQE DW 11
            admin_req[15] = ["CAPL",                     DW11,                                                                       "Capacity Lower"]
            # SQE DW 12
            admin_req[16] = ["CAPU",                     DW12,                                                                       "Capacity Upper"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x24) or (admin_req[0][1] == 0x24):    # "Lockdown",
            # SQE DW 10
            admin_req[13] = ["SCP",                     (DW10 & 0x0F),                                                                       "Scope"]
            admin_req[14] = ["PRHBT",                     bool(DW10 & 0x10),                                                                       "Prohibit"]
            admin_req[15] = ["IFC",                     (DW10 >> 5) & 0x03,                                                                       "Interface"]
            admin_req[16] = ["OFI",                     (DW10 >> 8) & 0xFF,                                                                       "Opcode or Feature Identifier"]
            # SQE DW 11
            # SQE DW 12
            # SQE DW 13
            # SQE DW 14
            admin_req[17] =  ["UIDX",                    DW14 & 0x7F,                                                                "UUID Index"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x28) or (admin_req[0][1] == 0x28):    # "Clear Exported NVM Resource Configuration",TBD
            # SQE DW 10
            # SQE DW 11
            # SQE DW 12
            # SQE DW 13
            # SQE DW 14
            # SQE DW 15
            admin_req[13] = ["DW10",                     DW10,                                                                       "DOWRD 10"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x2A) or (admin_req[0][1] == 0x2A):    # "Create Exported NVM Subsystem",
            # SQE DW 10
            admin_req[13] = ["RA",                     bool(DW10 & 0x100),                                                                       "Restricted Access"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x2D) or (admin_req[0][1] == 0x2D):    # "Manage Exported NVM Subsystem",
            # SQE DW 10
            admin_req[13] = ["SEL",                     (DW10 & 0xFF),                                                                       "Select"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x31) or (admin_req[0][1] == 0x31):    # "Manage Exported Namespace",
            # SQE DW 10
            admin_req[13] = ["SEL",                     (DW10 & 0xFF),                                                                       "Select"]
            admin_req[14] = ["MOS",                     (DW10 >> 8) & 0xFF,                                                                       "Management Operation Specific"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x35) or (admin_req[0][1] == 0x35):    # "Manage Exported Port",
            # SQE DW 10
            admin_req[13] = ["SEL",                     (DW10 & 0xFF),                                                                       "Select"]
            admin_req[14] = ["MOS",                     (DW10 >> 8) & 0xFF,                                                                       "Management Operation Specific"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x80) or (admin_req[0][1] == 0x80):    # "Format NVM",
            # SQE DW 10
            admin_req[13] = ["LBAFU",                (DW10 & 0xF),                                                                       "LBA Format Lower"]
            admin_req[14] = ["SES",                  (DW10 & 0x10),                                                                       "Metadata Settings"]
            admin_req[15] = ["PIL",                  (DW10 >> 5) & 0x7,                                                                       "Protection Information"]
            admin_req[16] = ["PI",                   (DW10 & 0x100),                                                                       "Protection Information Location"]
            admin_req[17] = ["MSET",                 (DW10 >> 5) & 0x7,                                                                       "Secure Erase Settings"]
            admin_req[18] = ["LBAFL",                (DW10 >> 12) & 0x3,                                                                       "LBA Format Upper"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x81) or (admin_req[0][1] == 0x81):    # "Security Send",
            # SQE DW 10
            admin_req[13] = ["NSFF",                     (DW10 >> 24) & 0xFF,                                                                       "NVMe Security Specific Field"]
            admin_req[14] = ["SPSP0",                     (DW10 >> 16) & 0xFF,                                                                       "SP Specific 0"]
            admin_req[15] = ["SPSP1",                     (DW10 >> 8) & 0xFF,                                                                       "SP Specific 1"]
            admin_req[16] = ["SECP",                     DW10 & 0xFF,                                                                       "Security Protocol"]
            # SQE DW 11
            admin_req[17] = ["TL",                     DW10,                                                                       "Transfer Length"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x82) or (admin_req[0][1] == 0x82):    # "Security Receive",
            # SQE DW 10
            admin_req[13] = ["NSFF",                     (DW10 >> 24) & 0xFF,                                                                       "NVMe Security Specific Field"]
            admin_req[14] = ["SPSP0",                     (DW10 >> 16) & 0xFF,                                                                       "SP Specific 0"]
            admin_req[15] = ["SPSP1",                     (DW10 >> 8) & 0xFF,                                                                       "SP Specific 1"]
            admin_req[16] = ["SECP",                     DW10 & 0xFF,                                                                       "Security Protocol"]
            # SQE DW 11
            admin_req[17] = ["AL",                     DW10,                                                                       "Allocation Length"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x84) or (admin_req[0][1] == 0x84):    # "Sanitize",
            # SQE DW 10
            admin_req[13] = ["SANACT",                     (DW10 & 0x07),                                                                       "Sanitize Action"]
            admin_req[14] = ["AUSE",                     bool(DW10 & 0x80),                                                                       "Allow Unrestricted Sanitize Exit"]
            admin_req[15] = ["OWPASS",                     (DW10 >> 4) & 0x0F,                                                                       "Overwrite Pass Count"]
            admin_req[16] = ["OIPBP",                     bool(DW10 & 0x100),                                                                       "Overwrite Invert Pattern Between Passes"]
            admin_req[17] = ["NDAS",                     bool(DW10 & 0x200),                                                                       "No-Deallocate After Sanitize"]
            admin_req[18] = ["EMVS",                     bool(DW10 & 0x400),                                                                       "Enter Media Verification State"]
            # SQE DW 11
            admin_req[19] = ["OVRPAT",                     DW11,                                                                       "Overwrite Pattern"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x86) or (admin_req[0][1] == 0x86):    # "Get LBA Status",
            # SQE DW 10
            admin_req[13] = ["SLBAL",                     DW10,                                                                       "Starting LBA Low"]
            # SQE DW 11
            admin_req[14] = ["SLBAU",                     DW11,                                                                       "Starting LBA Upeer"]
            # SQE DW 12
            admin_req[15] = ["MNDW",                     DW12,                                                                       "Maximum Number of Dwords"]
            # SQE DW 13
            admin_req[16] = ["RL",                     DW10 & 0xFFFF,                                                                       "Range Length"]
            admin_req[17] = ["ATYPE",                     (DW10 >> 24) & 0xFF,                                                                       "Action Type"]
        elif (admin_req[0][1] == 0x00 and self.LastOpcode == 0x8C) or (admin_req[0][1] == 0x8C):    # "Sanitize Namespace",
            # SQE DW 10
            admin_req[13] = ["SANACT",                     (DW10 & 0x07),                                                                       "Sanitize Action"]
            admin_req[14] = ["AUSE",                     bool(DW10 & 0x80),                                                                       "Allow Unrestricted Sanitize Exit"]
            admin_req[15] = ["EMVS",                     bool(DW10 & 0x400),                                                                       "Enter Media Verification State"]
        
        last_key = list(admin_req)[-1]

        admin_req[last_key + 1] = ["RD",                        0,                                          "Request Data"]
        if self.SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_req[last_key + 1][1] = i | (admin_req[last_key + 1][1] << 8)
        else:
            for i in data[64: Len]:
                admin_req[last_key + 1][1] = i | (admin_req[last_key + 1][1] << 8)
        
        return admin_req

    def handle_request_nvme_admin_command(self, data, firstPacket, Offset):
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data + [0 for i in range(len(Payload), 4224)]
        admin_req = self.handle_req_nvme_admin_parser(Payload, Offset, len(data))
        if self.SOM == 1 :
            self.LastOpcode = admin_req[0][1]
        AdminCommand = NVME_ADMIN_OPCODES.get(admin_req[0][1], 'Reserved')
        AdminDataPrint = {
            0 :[14, ['Opcode', 'Opc', 'O']],
            1 :[3, ['%s: %s | %s ► %s: %r → %s: %r → %s: %r | %s % 04X' % (admin_req[0][2], AdminCommand, admin_req[1][2], admin_req[1][1], admin_req[2][2], admin_req[3][2], admin_req[3][1], admin_req[4][2], admin_req[4][1], admin_req[5][2], admin_req[5][1]), '%s: %s | %s ► %s: %r → %s: %r → %s: %r | %s % 04X' % (admin_req[0][0], AdminCommand, admin_req[1][0], admin_req[1][1], admin_req[2][0], admin_req[3][0], admin_req[3][1], admin_req[4][0], admin_req[4][1], admin_req[5][0], admin_req[5][1]),  '%s | %s ► %s → %s → %s | %s' % (admin_req[0][0], admin_req[1][0], admin_req[2][0], admin_req[3][0], admin_req[4][0], admin_req[5][0]), 'opc']],
            2 :[14, ['DWORD 1', 'DW 1', 'D1']],
            3 :[4, ['%s: %08X' % (admin_req[6][2], admin_req[6][1]), '%s: %08X' % (admin_req[6][0], admin_req[6][1]), '%s' % admin_req[6][0], 'DW1']],
            4 :[14, ['DWORD 2', 'DW 2', 'D2']],
            5 :[4, ['%s: %08X' % (admin_req[7][2], admin_req[7][1]), '%s: %08X' % (admin_req[7][0], admin_req[7][1]), '%s' % admin_req[7][0], 'DW2']],
            6 :[14, ['DWORD 3', 'DW 3', 'D3']],
            7 :[4, ['%s: %08X' % (admin_req[8][2], admin_req[8][1]), '%s: %08X' % (admin_req[8][0], admin_req[8][1]), '%s' % admin_req[8][0], 'DW3']],
            8 :[14, ['DWORD 4', 'DW 4', 'D4']],
            9 :[4, ['%s: %08X' % (admin_req[9][2], admin_req[9][1]), '%s: %08X' % (admin_req[9][0], admin_req[9][1]), '%s' % admin_req[9][0], 'DW4']],
            10 :[14, ['DWORD 5', 'DW 5', 'D5']],
            11 :[4, ['%s: %08X' % (admin_req[10][2], admin_req[10][1]), '%s: %08X' % (admin_req[10][0], admin_req[10][1]), '%s' % admin_req[10][0], 'DW5']],
            12 :[14, ['Data Offset', 'DOFST', 'DO']],
            13 :[4, ['%s: %08X' % (admin_req[11][2], admin_req[11][1]), '%s: %08X' % (admin_req[11][0], admin_req[11][1]), '%s' % admin_req[11][0], 'DOFST']],
            14 :[14, ['Data Length', 'DLEN', 'DL']],
            15 :[4, ['%s: %08X' % (admin_req[12][2], admin_req[12][1]), '%s: %08X' % (admin_req[12][0], admin_req[12][1]), '%s' % admin_req[12][0], 'DLEN']],
            16 :[14, ['Reserved', 'RSVD', 'R']],
            17 :[4, ['Reserved: 00 00 00 00',   'RSVD: 00 00 00 00',    '0000 0000',    'RSVD']],
            18 :[14, ['Reserved', 'RSVD', 'R']],
            19 :[4, ['Reserved: 00 00 00 00',   'RSVD: 00 00 00 00',    '0000 0000',    'RSVD']],
            20 :[14, ['DWORD 10', 'DW 10', 'D10']],
            21 :[],
            22 :[14, ['DWORD 11', 'DW 11', 'D11']],
            23 :[],
            24 :[14, ['DWORD 12', 'DW 12', 'D12']],
            25 :[],
            26 :[14, ['DWORD 13', 'DW 13', 'D13']],
            27 :[],
            28 :[14, ['DWORD 14', 'DW 14', 'D14']],
            29 :[],
            30 :[14, ['DWORD 15', 'DW 15', 'D15']],
            31 :[],
            32 :[14, ['Response Data', 'Res Data', 'RQ']],
            33 :[4, ['%s: %X' % (admin_req[12][2], admin_req[12][1]), '%s: %X' % (admin_req[12][0], admin_req[12][1]), '%s' % (admin_req[12][0]), 'RD']],
        }
        
        if self.LastOpcode == 0x02:      # "Get Log Page",
            DWORD10 = [
            '%s: %02X | %s: %r | %s: %02X | %s: %02X' % (admin_req[13][2], admin_req[13][1], admin_req[14][2], admin_req[14][1], admin_req[15][2], admin_req[15][1], admin_req[16][2], admin_req[16][1]),
            '%s: %02X | %s: %r | %s: %02X | %s: %02X' % (admin_req[13][0], admin_req[13][1], admin_req[14][0], admin_req[14][1], admin_req[15][0], admin_req[15][1], admin_req[16][0], admin_req[16][1]),
            '%s | %s | %s | %s' % (admin_req[13][0], admin_req[14][0], admin_req[15][0], admin_req[16][0]),
            'DW10']
            DWORD11 = [
            '%s: %04X | %s: %04X' % (admin_req[17][2], admin_req[17][1], admin_req[18][2], admin_req[18][1]),
            '%s: %04X | %s: %04X' % (admin_req[17][0], admin_req[17][1], admin_req[18][0], admin_req[18][1]),
            '%s | %s' % (admin_req[17][0], admin_req[18][0]),
            'DW11']
            DWORD12 = [
            '%s: %08X' % (admin_req[19][2], admin_req[19][1]),
            '%s: %08X' % (admin_req[19][0], admin_req[19][1]),
            '%s' % (admin_req[19][0]),
            'DW12']
            DWORD13 = [
            '%s: %08X' % (admin_req[20][2], admin_req[20][1]),
            '%s: %08X' % (admin_req[20][0], admin_req[20][1]),
            '%s' % (admin_req[20][0]),
            'DW13']
            DWORD14 = [
            '%s: %02X | %s: %r | %s: %02X' % (admin_req[21][2], admin_req[21][1], admin_req[22][2], admin_req[22][1], admin_req[23][2], admin_req[23][1]),
            '%s: %02X | %s: %r | %s: %02X' % (admin_req[21][0], admin_req[21][1], admin_req[22][0], admin_req[22][1], admin_req[23][0], admin_req[23][1]),
            '%s | %s | %s' % (admin_req[21][0], admin_req[22][0], admin_req[23][0]),
            'DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x06:    # "Identify",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x09:    # "Set Features",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x0A:    # "Get Features",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x0D:    # "Namespace Management",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x10:    # "Firmware Commit",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x11:    # "Firmware Image Download",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x14:    # "Device Self-Test",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x15:    # "Namespace attachment",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x1C:    # "Virtualization Management",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x20:    # "Capacity Management",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x24:    # "Lockdown",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x28:    # "Clear Exported NVM Resource Configuration",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x2A:    # "Create Exported NVM Subsystem",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x2D:    # "Manage Exported NVM Subsystem",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x31:    # "Manage Exported Namespace",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x35:    # "Manage Exported Port",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x80:    # "Format NVM",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x81:    # "Security Send",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x82:    # "Security Receive",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x84:    # "Sanitize",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x86:    # "Get LBA Status",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        elif self.LastOpcode == 0x8C:    # "Sanitize Namespace",
            DWORD10 = ['%s: %08X' % (admin_req[1][2], admin_req[1][1]), '%s: %08X' % (admin_req[1][0], admin_req[1][1]), '%s' % admin_req[1][0], 'DW10']
            DWORD11 = ['DW11']
            DWORD12 = ['DW12']
            DWORD13 = ['DW13']
            DWORD14 = ['DW14']
            DWORD15 = ['DW15']
        
        AdminDataPrint[21] = [4, DWORD10]
        AdminDataPrint[23] = [4, DWORD11]
        AdminDataPrint[25] = [4, DWORD12]
        AdminDataPrint[27] = [4, DWORD13]
        AdminDataPrint[29] = [4, DWORD14]
        AdminDataPrint[31] = [4, DWORD15]
        
        j = (Offset/4) * 2 # (Offset / 4) is equal to dword N requested and *2  is the table position.

        if j >= 32:
            self.put(self.packets[firstPacket][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, AdminDataPrint[32])
            self.put(self.packets[firstPacket][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, AdminDataPrint[33])
        else:
            for i in range(firstPacket, firstPacket + len(data) - 3, 4):
                if j == 32:
                    i -= 4
                    break
                else:
                    self.put(self.packets[i][0], self.packets[i + 3][1], self.out_ann, AdminDataPrint[j])
                    self.put(self.packets[i][0], self.packets[i + 3][1], self.out_ann, AdminDataPrint[j + 1])
                    j += 2
            i = firstPacket if i == 0 else i + 4
            self.put(self.packets[i][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, AdminDataPrint[j])
            self.put(self.packets[i][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, AdminDataPrint[j + 1])

    def handle_request_pcie_command(self):
        return
        
    def handle_request_asynchronous_event(self):
        return

# ------------- Response Messages
    def handle_resp_ctrl_prim_parser(self, data):
        ctrl_prim_resp = {
            0 :                 ["STA",                     data[0],                                    "Status"],
            1 :                 ["TAG",                     data[1],                                    "Tag"],
        }
        payload = data[2] | (data[3] << 8)
        
    # "Pause"
        if self.LastOpcode == 0x00:
            # CPSR 
            ctrl_prim_resp[2] = ["PFSS0",   bool(payload & 0x01),           "Pause Flag Status Slot 0"]
            ctrl_prim_resp[3] = ["PFSS1",   bool((payload >> 1) & 0x01),    "Pause Flag Status Slot 1"]
    # "Abort",
        elif self.LastOpcode == 0x02:
            # CPSR
            ctrl_prim_resp[2] = ['CPAS',    (payload & 0x03),               'Command Processing Abort Status']
    # "Get State",
        elif self.LastOpcode == 0x03:
            # CPSR
            ctrl_prim_resp[2] = ["MES",     payload,                        "Management Endpoint State"]
            ctrl_prim_resp[3] = ["SSTA",    (payload & 0x03),               "       Slot Command Servicing State"]
            ctrl_prim_resp[4] = ["CMNICS",  bool((payload >> 3) & 0x01),    "       Command Message to non-Idle Command Slot"]
            ctrl_prim_resp[5] = ["BMICE",   bool((payload >> 4) & 0x01),    "       Bad Message Integrity Check Error"]
            #Obsolete       
            ctrl_prim_resp[6] = ["WPTT",    bool((payload >> 5) & 0x01),    "       Timeout Waiting for a Packet"]
            ctrl_prim_resp[7] = ["UTUNT",   bool((payload >> 6) & 0x01),    "       Unsupported Transmission Unit"]
            ctrl_prim_resp[8] = ["BHVS",    bool((payload >> 7) & 0x01),    "       Bad Header Version"]
            ctrl_prim_resp[9] = ["UDSTID",  bool((payload >> 8) & 0x01),    "       Unknown Destination ID"]
            ctrl_prim_resp[10] = ["ITU",    bool((payload >> 9) & 0x01),    "       Incorrect Transmission Unit"]
            ctrl_prim_resp[11] = ["UMEP",   bool((payload >> 10) & 0x01),   "       Unexpected Middle or End of Packet"]
            ctrl_prim_resp[12] = ["OSPSN",  bool((payload >> 11) & 0x01),   "       Out-of-Sequence Packet Sequence Number"]
            ctrl_prim_resp[13] = ["BUEMT",  bool((payload >> 12) & 0x01),   "       Bad, Unexpected, or Expired Message Tag"]
            ctrl_prim_resp[14] = ["BPOPL",  bool((payload >> 13) & 0x01),   "       Bad Packet or Other Physical Layer"]
            ctrl_prim_resp[15] = ["NSSRO",  bool((payload >> 14) & 0x01),   "       NVM Subsystem Reset Occurred"]
            ctrl_prim_resp[16] = ["PFLG",   bool((payload >> 15) & 0x01),   "       Pause Flag"]
    # "Replay",
        elif self.LastOpcode == 0x04:
            # CPSR
            ctrl_prim_resp[2] = ['RR',      bool(payload & 0x01),           'Response Replay']
        
        return ctrl_prim_resp

    def handle_response_control_primitive(self):
        Data = [self.packets[j][3] for j in range(12, len(self.packets))]
        ctrl_prim_resp = self.handle_resp_ctrl_prim_parser(Data)
        NVMeMiStatus = NVME_MI_STATUS.get(ctrl_prim_resp[0][1], 'Reserved')
        self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [14, ['Control Primitive Response', 'Ctrl Prim Resp', 'CRP']])

    # "Pause"
        if self.LastOpcode == 0x00:
            self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [4, 
            ['Status: %s | TAG: %02X | PFSS0: %r | PFSS1: %r' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1], ctrl_prim_resp[2][1], ctrl_prim_resp[3][1]), 
            '%s| TAG: %02X | PFSS0: %d | PFSS1: %d' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1], ctrl_prim_resp[2][1], ctrl_prim_resp[3][1]), 
            'Sta|Tag|PFSS0-1', 
            'CPP']])
    # "Resume",
        elif self.LastOpcode == 0x01:
            self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [4, 
            ['Status: %s | TAG: %02X' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1]), 
            '%s| TAG: %02X' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1]), 
            'Sta|Tag', 
            'CPP']])
    # "Abort",
        elif self.LastOpcode == 0x02:
            self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [4, 
            ['Status: %s | TAG: %02X | Command Processing Abort Status: %d' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1], ctrl_prim_resp[2][1]), 
            '%s| TAG: %02X | CPAS: %d' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1], ctrl_prim_resp[2][1]), 
            'Sta|Tag|CPAS', 
            'CPP']])
    # "Get State",
        elif self.LastOpcode == 0x03:
            self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [4, 
            ['Status: %s | TAG: %02X | SSTA: %d | CMNICS: %r | BMICE: %r | WPTT: %r | UTUNT: %r | BHVS: %r | UDSTID: %r | ITU: %r | UMEP: %r | OSPSN: %r | BUEMT: %r | BPOPL: %r | NSSRO: %r | PFLG: %r' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1], ctrl_prim_resp[3][1], ctrl_prim_resp[4][1], ctrl_prim_resp[5][1], ctrl_prim_resp[6][1], ctrl_prim_resp[7][1], ctrl_prim_resp[8][1], ctrl_prim_resp[9][1], ctrl_prim_resp[10][1], ctrl_prim_resp[11][1], ctrl_prim_resp[12][1], ctrl_prim_resp[13][1], ctrl_prim_resp[14][1], ctrl_prim_resp[15][1], ctrl_prim_resp[16][1]), 
            '%s| TAG: %02X | Flags: %04X' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1], ctrl_prim_resp[2][1]),
            'Sta|Tag|Flags', 
            'CPP']])
    # "Replay",
        elif self.LastOpcode == 0x04:
            self.put(self.packets[12][0], self.packets[15][1], self.out_ann, [4, 
            ['Status: %s | TAG: %02X | Response Replay: %r' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1], ctrl_prim_resp[2][1]), 
            '%s| TAG: %02X | RR: %d' % 
            (NVMeMiStatus, ctrl_prim_resp[1][1], ctrl_prim_resp[2][1]), 
            'Sta|Tag|RR', 
            'CPP']])

    def handle_resp_nvme_mi_parser(self, data, Offset, Len):
        nvme_mi_resp = {
            0 :                 ["STA",                     data[0],                                                        "Status"],
        }
        NVMeMngResp = data[1] | (data[2] << 8) | (data[3] << 16)

    # "Read NVMe-MI Data Structure"
        if self.LastOpcode == 0x00:
            # NVMe Managment Response
            nvme_mi_resp[1] = ["RDL",                       (NVMeMngResp & 0xFFFF),                                         "Response Data Length"]
            if self.LastDytp == 0x00:   # NVM Subsystem Information
                nvme_mi_resp[2] = ["NUMP",                  data[4],                                                        "Number of Ports"]
                nvme_mi_resp[3] = ["MJR",                   data[5],                                                        "NVMe-MI Major Version Number"]
                nvme_mi_resp[4] = ["MNR",                   data[6],                                                        "NVMe-MI Minor Version Number"]
                nvme_mi_resp[5] = ["NNSC",                  data[7],                                                        "NVMe-MI NVM Subsystem Capabilities"]
                nvme_mi_resp[6] = ["SRE",                   bool(nvme_mi_resp[5][1] & 0x1),                                 "       Status Reporting Enhancements"]
            elif self.LastDytp == 0x01: # Port Information
                nvme_mi_resp[2] = ["PRTTYP",                data[4],                                                        "Port Type"]
                nvme_mi_resp[3] = ["PRTCAP",                data[5],                                                        "Port Capabilities"]
                nvme_mi_resp[4] = ["AEMS",                  bool((nvme_mi_resp[3][1] >> 1) & 0x1),                          "       Asynchronous Event Messages Supported"]
                nvme_mi_resp[5] = ["CIAPS",                 bool(nvme_mi_resp[3][1] & 0x1),                                 "       Command Initiated Auto Pause Supported"]
                nvme_mi_resp[6] = ["MMTUS",                 data[6] | (data[7] << 8),                                       "Maximum MCTP Transmission Unit Size"]
                nvme_mi_resp[7] = ["MEBS",                  data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24), "Management Endpoint Buffer Size"]
                if nvme_mi_resp[2][1] == 0x01: # PCIe Port Specific Data
                    nvme_mi_resp[8] = ["PCIEMPS",           data[12],                                                       "PCIe Maximum Payload Size"]
                    nvme_mi_resp[9] = ["PCIESLSV",          data[13],                                                       "PCIe Supported Link Speeds Vector"]
                    nvme_mi_resp[10] = ["GTS64",            bool((nvme_mi_resp[9][1] >> 5) & 0x1),                          "       64.0 GT/s Support"]
                    nvme_mi_resp[11] = ["GTS32",            bool((nvme_mi_resp[9][1] >> 4) & 0x1),                          "       32.0 GT/s Support"]
                    nvme_mi_resp[12] = ["GTS16",            bool((nvme_mi_resp[9][1] >> 3) & 0x1),                          "       16.0 GT/s Support"]
                    nvme_mi_resp[13] = ["GTS8",             bool((nvme_mi_resp[9][1] >> 2) & 0x1),                          "       8.0 GT/s Support"]
                    nvme_mi_resp[14] = ["GTS5",             bool((nvme_mi_resp[9][1] >> 1) & 0x1),                          "       5.0 GT/s Support"]
                    nvme_mi_resp[15] = ["GTS2P5",           bool(nvme_mi_resp[9][1] & 0x1),                                 "       2.5 GT/s Support"]
                    nvme_mi_resp[16] = ["PCIECLS",          data[14],                                                       "PCIe Current Link Speed"]
                    nvme_mi_resp[17] = ["PCIEMLW",          data[15],                                                       "PCIe Maximum Link Width"]
                    nvme_mi_resp[18] = ["PCIENLW",          data[16],                                                       "PCIe Negotiated Link Width"]
                    nvme_mi_resp[19] = ["PCIEPN",           data[17],                                                       "PCIe Port Number"]
                elif nvme_mi_resp[2][1] == 0x02:   # 2-Wire Port Specific Data
                    nvme_mi_resp[8] = ["CVPDADDR",          data[12],                                                       "Current VPD Address"]
                    nvme_mi_resp[9] = ["MVPDFREQ",          data[13],                                                       "Maximum VPD Access Frequency"]
                    nvme_mi_resp[10] = ["CMEADDR",          data[14],                                                       "Current Management Endpoint Address"]
                    nvme_mi_resp[11] = ["TWPRT",            data[15],                                                       "2-Wire Protocols Supported"]
                    nvme_mi_resp[12] = ["I3CSPRT",          bool((nvme_mi_resp[11][1] >> 7) & 0x1),                         "       I3C Support"]
                    nvme_mi_resp[13] = ["MSMBFREQ",         (nvme_mi_resp[11][1] & 0x3),                                    "       Maximum SMBus/I2C Frequency"]
                    nvme_mi_resp[14] = ["NVMEBMS",          data[16],                                                       "NVMe Basic Management Support"]
            elif self.LastDytp == 0x02: # Controller List
                nvme_mi_resp[2] = ["NUMCIDS",               data[4] | (data[5] << 8),                                       "Number of Controller Identifiers"]
                j = 6
                for i in range(0, nvme_mi_resp[2][1]):
                    nvme_mi_resp[i + 3] = ["CID %d" % i,    data[j] | (data[j + 1] << 8),                                   "Controller Identifier %d" % i]
                    j += 2
            elif self.LastDytp == 0x03: # Controller Information
                nvme_mi_resp[2] = ["PORTID",                data[4],                                                        "Port Identifier"]
                nvme_mi_resp[3] = ["PRII",                  data[9],                                                        "PCIe Routing ID Information"]
                nvme_mi_resp[4] = ["PCIERIV",               bool(nvme_mi_resp[3][1] & 0x1),                                 "       PCIe Routing ID Valid"]
                nvme_mi_resp[5] = ["PRI",                   data[10] | (data[11] << 8),                                     "PCIe Routing ID"]
                nvme_mi_resp[6] = ["PCIBN",                 ((nvme_mi_resp[5][1] >> 8) & 0xFF),                             "       PCI Bus Number"]
                nvme_mi_resp[7] = ["PCIDN",                 ((nvme_mi_resp[5][1] >> 3) & 0x1F),                             "       PCI Device Number"]
                nvme_mi_resp[8] = ["PCIFN",                 (nvme_mi_resp[5][1] & 0x7),                                     "       PCI Function Number"]
                nvme_mi_resp[9] = ["PCIVID",                data[12] | (data[13] << 8),                                     "PCI Vendor ID"]
                nvme_mi_resp[10] = ["PCIDID",               data[14] | (data[15] << 8),                                     "PCI Device ID"]
                nvme_mi_resp[11] = ["PCISVID",              data[16] | (data[17] << 8),                                     "PCI Subsystem Vendor ID"]
                nvme_mi_resp[12] = ["PCISDID",              data[18] | (data[19] << 8),                                     "PCI Subsystem Device ID"]
                nvme_mi_resp[13] = ["PCIESN",               data[20],                                                       "PCIe Segment Number"]
            elif self.LastDytp == 0x04: # Optionally Supported Command List
                    nvme_mi_resp[2] = ["NUMCMD",            data[4] | (data[5] << 8),                                       "Number of Commands"]
                    j = 6
                    k = 3
                    for i in range(0, nvme_mi_resp[2][1]):
                        nvme_mi_resp[k] = ["CMD %d" % i,    data[j] | (data[j + 1] << 8),                                   "Command %d" % i]
                        nvme_mi_resp[k + 1] = ["NMIMT",     (nvme_mi_resp[k][1] >> 3) & 0xF,                                "       NVMe-MI Message Type"]
                        nvme_mi_resp[k + 2] = ["OPC",       (nvme_mi_resp[k][1] >> 8) & 0xFF,                               "       Opcode"]
                        j += 2
                        k += 3
            elif self.LastDytp == 0x05: # Management Endpoint Buffer Command Support List
                    nvme_mi_resp[2] = ["NUMCMD",            data[4] | (data[5] << 8),                                       "Number of Commands"]
                    j = 6
                    k = 3
                    for i in range(3, nvme_mi_resp[2][1]):
                        nvme_mi_resp[k] = ["CMD %d" % i,    data[j] | (data[j + 1] << 8),                                   "Command %d" % i]
                        nvme_mi_resp[k + 1] = ["NMIMT",     (nvme_mi_resp[k][1] >> 3) & 0xF,                                "       NVMe-MI Message Type"]
                        nvme_mi_resp[k + 2] = ["OPC",       (nvme_mi_resp[k][1] >> 8) & 0xFF,                               "       Opcode"]
                        j += 2
                        k += 3
    # "NVM Subsystem Health Status Poll",
        elif self.LastOpcode == 0x01:
            nvme_mi_resp[1] = ["NSS",                       data[4],                                                        "NVM Subsystem Status"]
            nvme_mi_resp[2] = ["ATF",                       bool((nvme_mi_resp[1][1] >> 7) & 0x1),                          "      AEM Transmission Failure"]
            nvme_mi_resp[3] = ["SFM",                       bool((nvme_mi_resp[1][1] >> 6) & 0x1),                          "      Sanitize Failure Mode"]
            nvme_mi_resp[4] = ["DF",                        bool((nvme_mi_resp[1][1] >> 5) & 0x1),                          "      Drive Functional"]
            nvme_mi_resp[5] = ["RNR",                       bool((nvme_mi_resp[1][1] >> 4) & 0x1),                          "      Reset Not Required"]
            nvme_mi_resp[6] = ["P0LA",                      bool((nvme_mi_resp[1][1] >> 3) & 0x1),                          "      Port 0 PCIe Link Active"]
            nvme_mi_resp[7] = ["P1LA",                      bool((nvme_mi_resp[1][1] >> 2) & 0x1),                          "      Port 1 PCIe Link Active"]
            nvme_mi_resp[8] = ["SNFM",                      bool((nvme_mi_resp[1][1] >> 1) & 0x1),                          "      Sanitize Namespace Failure Mode"]
            nvme_mi_resp[9] = ["SW",                        data[5],                                                        "SMART Warnings"]
            nvme_mi_resp[10] = ["CTEMP",                    data[6],                                                        "Composite Temperature"]
            nvme_mi_resp[11] = ["PDLU",                     data[7],                                                        "Percentage Drive Life Used"]
            nvme_mi_resp[12] = ["CCS",                      data[8] | (data[9] << 8),                                       "Composite Controller Status Flags"]
            nvme_mi_resp[13] = ["TCIDA",                    bool((nvme_mi_resp[12][1] >> 13) & 0x1),                        "      Telemetry Controller-Initiated Data Available"]
            nvme_mi_resp[14] = ["CWARN",                    bool((nvme_mi_resp[12][1] >> 12) & 0x1),                        "      Critical Warning"]
            nvme_mi_resp[15] = ["SPARE",                    bool((nvme_mi_resp[12][1] >> 11) & 0x1),                        "      Available Spare"]
            nvme_mi_resp[16] = ["PDLU",                     bool((nvme_mi_resp[12][1] >> 10) & 0x1),                        "      Percentage Used"]
            nvme_mi_resp[17] = ["CTEMP",                    bool((nvme_mi_resp[12][1] >> 9) & 0x1),                         "      Composite Temperature Change"]
            nvme_mi_resp[18] = ["CSTS",                     bool((nvme_mi_resp[12][1] >> 8) & 0x1),                         "      Controller Status Change"]
            nvme_mi_resp[19] = ["FA",                       bool((nvme_mi_resp[12][1] >> 7) & 0x1),                         "      Firmware Activated"]
            nvme_mi_resp[20] = ["NAC",                      bool((nvme_mi_resp[12][1] >> 6) & 0x1),                         "      Namespace Attribute Changed"]
            nvme_mi_resp[21] = ["CECO",                     bool((nvme_mi_resp[12][1] >> 5) & 0x1),                         "      Controller Enable Change Occurred"]
            nvme_mi_resp[22] = ["NSSRO",                    bool((nvme_mi_resp[12][1] >> 4) & 0x1),                         "      NVM Subsystem Reset Occurred"]
            nvme_mi_resp[23] = ["SHST",                     bool((nvme_mi_resp[12][1] >> 2) & 0x1),                         "      Shutdown Status"]
            nvme_mi_resp[24] = ["CFS",                      bool((nvme_mi_resp[12][1] >> 1) & 0x1),                         "      Controller Fatal Status"]
            nvme_mi_resp[25] = ["RDY",                      bool(nvme_mi_resp[12][1] & 0x1),                                "      Ready"]
    # "Controller Health Status Poll", TBD
        elif self.LastOpcode == 0x02:
            # NVMe Managment Response
            nvme_mi_resp[1] = ["RENT",                      (NVMeMngResp >> 16) & 0xFF,                                     "Response Entries"]
            # Response Data
            nvme_mi_resp[2] = ["CTLID",                     data[4] | (data[5] << 8),                                       "Controller Identifier"]
            nvme_mi_resp[3] = ["CSTS",                      data[6] | (data[7] << 8),                                       "Controller Status"]
            nvme_mi_resp[4] = ["TCIDA",                     bool((nvme_mi_resp[3][1] >> 8) & 0x01),                         "       Telemetry Controller-Initiated Data Available"]
            nvme_mi_resp[5] = ["FA",                        bool((nvme_mi_resp[3][1] >> 7) & 0x01),                         "       Firmware Activated"]
            nvme_mi_resp[6] = ["NAC",                       bool((nvme_mi_resp[3][1] >> 6) & 0x01),                         "       Namespace Attribute Changed"]
            nvme_mi_resp[7] = ["CECO",                      bool((nvme_mi_resp[3][1] >> 5) & 0x01),                         "       Controller Enable Change Occurred"]
            nvme_mi_resp[8] = ["NSSRO",                     bool((nvme_mi_resp[3][1] >> 4) & 0x01),                         "       NVM Subsystem Reset Occurred"]
            nvme_mi_resp[9] = ["SHST",                      (nvme_mi_resp[3][1] >> 2) & 0x03,                               "       Shutdown Status"]
            nvme_mi_resp[10] = ["CFS",                      bool((nvme_mi_resp[3][1] >> 1) & 0x01),                         "       Controller Fatal Status"]
            nvme_mi_resp[11] = ["RDY",                      bool(nvme_mi_resp[3][1] & 0x01),                                "       Ready"]
            nvme_mi_resp[12] = ["CTEMP",                    data[8] | (data[9] << 8),                                       "Composite Temperature"]
            nvme_mi_resp[13] = ["PDLU",                     data[10],                                                       "Percentage Used"]
            nvme_mi_resp[14] = ["SPARE",                    data[11],                                                       "Available Spare"]
            nvme_mi_resp[15] = ["CWARM",                    data[12],                                                       "Critical Warning"]
            nvme_mi_resp[16] = ["IPS",                      bool((nvme_mi_resp[15][1] >> 6) & 0x01),                        "       Indeterminate Personality State"]
            nvme_mi_resp[17] = ["PMRE",                     bool((nvme_mi_resp[15][1] >> 5) & 0x01),                        "       Persistent Memory Region Error"]
            nvme_mi_resp[18] = ["VMBF",                     bool((nvme_mi_resp[15][1] >> 4) & 0x01),                        "       Volatile Memory Backup Failed"]
            nvme_mi_resp[19] = ["RO",                       bool((nvme_mi_resp[15][1] >> 3) & 0x01),                        "       Read Only"]
            nvme_mi_resp[20] = ["RD",                       bool((nvme_mi_resp[15][1] >> 2) & 0x01),                        "       Reliability Degraded"]
            nvme_mi_resp[21] = ["TAUT",                     bool((nvme_mi_resp[15][1] >> 1) & 0x01),                        "       Temperature Above or Under Threshold"]
            nvme_mi_resp[22] = ["ST",                       bool(nvme_mi_resp[15][1] & 0x01),                               "       Spare Threshold"]
            nvme_mi_resp[23] = ["CHSC",                     data[13] | (data[14] << 8),                                     "Controller Health Status Changed"]
            nvme_mi_resp[24] = ["TCIDA",                    bool((nvme_mi_resp[23][1] >> 13) & 0x1),                        "       Telemetry Controller-Initiated Data Available"]
            nvme_mi_resp[25] = ["CWARN",                    bool((nvme_mi_resp[23][1] >> 12) & 0x1),                        "       Critical Warning"]
            nvme_mi_resp[26] = ["SPARE",                    bool((nvme_mi_resp[23][1] >> 11) & 0x1),                        "       Available Spare"]
            nvme_mi_resp[27] = ["PDLU",                     bool((nvme_mi_resp[23][1] >> 10) & 0x1),                        "       Percentage Used"]
            nvme_mi_resp[28] = ["CTEMP",                    bool((nvme_mi_resp[23][1] >> 9) & 0x1),                         "       Composite Temperature Change"]
            nvme_mi_resp[29] = ["CSTS",                     bool((nvme_mi_resp[23][1] >> 8) & 0x1),                         "       Controller Status Change"]
            nvme_mi_resp[30] = ["FA",                       bool((nvme_mi_resp[23][1] >> 7) & 0x1),                         "       Firmware Activated"]
            nvme_mi_resp[31] = ["NAC",                      bool((nvme_mi_resp[23][1] >> 6) & 0x1),                         "       Namespace Attribute Changed"]
            nvme_mi_resp[32] = ["CECO",                     bool((nvme_mi_resp[23][1] >> 5) & 0x1),                         "       Controller Enable Change Occurred"]
            nvme_mi_resp[33] = ["NSSRO",                    bool((nvme_mi_resp[23][1] >> 4) & 0x1),                         "       NVM Subsystem Reset Occurred"]
            nvme_mi_resp[34] = ["SHST",                     bool((nvme_mi_resp[23][1] >> 2) & 0x1),                         "       Shutdown Status"]
            nvme_mi_resp[35] = ["CFS",                      bool((nvme_mi_resp[23][1] >> 1) & 0x1),                         "       Controller Fatal Status"]
            nvme_mi_resp[36] = ["RDY",                      bool(nvme_mi_resp[23][1] & 0x1),                                "       Ready"]
    # "Configuration Set"
        elif self.LastOpcode == 0x03:
            if self.LastCID == 0x04:
                # Response Data
                # AE Occurence List Data Structure
                # if the AE Occurrence List Overflow = ‘1’, then the AE Occurrence List data structure = AE Occurrence List Header and shall not contain an AE Occurrence List Body.
                ## AE Occurrence List Header
                nvme_mi_resp[1] = ["NUMAEO",                data[4],                                                        "Number of AE Occurrence Data Structures"]
                nvme_mi_resp[2] = ["AELVER",                data[5],                                                        "AE Occurrence List Version Number"]
                nvme_mi_resp[3] = ["AEOLLI",                data[6] | (data[7] << 8) | (data[8] << 16),                     "AE Occurrence List Length Info"]
                nvme_mi_resp[5] = ["AEOLTL",                nvme_mi_resp[3][1] & 0x7FFFFF,                                  "       AE Occurrence List Total Length"]
                nvme_mi_resp[4] = ["AEOLO",                 bool(nvme_mi_resp[3][1] >> 23) & 0x01,                          "       AE Occurrence List Overflow"]
                nvme_mi_resp[6] = ["AEOLHL",                data[9],                                                        "AE Occurrence List Header Length"]
                nvme_mi_resp[7] = ["AEMTI",                 data[10],                                                       "AEM Transmission Info"]
                nvme_mi_resp[8] = ["AEMGN",                 (nvme_mi_resp[7][1] >> 3) & 0x1F,                               "       AEM Generation Number"]
                nvme_mi_resp[9] = ["AEMRC",                 nvme_mi_resp[7][1] & 0x7,                                       "       AEM Retry Count"]
                if nvme_mi_resp[4][1] == 0: #AEOLO = 0
                    ## AE Occurrence List Body
                    # AE Occurence N
                    j = 11
                    m = 10
                    for i in range(0, nvme_mi_resp[1][1]):
                        # AE Occurrence Header
                        nvme_mi_resp[m] = ["AELHLEN",       data[j],                                                        "AE Occurrence Header Length"]
                        nvme_mi_resp[m + 1] = ["AEOSIL",    data[j + 1],                                                    "AE Occurrence Specific Info Length"]
                        nvme_mi_resp[m + 2] = ["AEOVSIL",   data[j + 2],                                                    "AE Occurrence Vendor Specific Info Length"]
                        # AE Occurence Unique ID AEOUI
                        nvme_mi_resp[m + 3] = ["AEOI",      data[j + 3],                                                    "AE Occurrence ID"]
                        nvme_mi_resp[m + 4] = ["AEOCIDI",   (data[j + 4] | (data[j + 5] << 8) | (data[j + 6] << 16) | (data[j + 7] << 24)),    "AE Occurrence Scope ID Info"]
                        nvme_mi_resp[m + 5] = ["AESSI",     data[j + 8],                                                    "AE Occurrence Scope Info"]
                        nvme_mi_resp[m + 6] = ["AESS",      (nvme_mi_resp[m + 5][1] & 0xF),                                 "       AE Occurrence Scope"]
                        AEOSIL, AEOVSIL = nvme_mi_resp[m + 1][1], nvme_mi_resp[m + 2][1]
                        j += 9
                        m += 7
                        # AE Occurence Specific Info
                        if AEOSIL != 0:
                            nvme_mi_resp[m] = ["AEOSI",     0,                                                              "AE Occurrence Specific Info"]
                            for k in range(0, AEOSIL):
                                nvme_mi_resp[m][1] = data[j + k] | (nvme_mi_resp[m][1] << 8)
                            j += AEOSIL
                            m += 1
                        # AE Occurence Vendor Specific Info
                        if AEOVSIL != 0:
                            nvme_mi_resp[m] = ["AEOVSI",    0,                                                              "AE Occurrence Vendor Specific Info"]
                            for k in range(0, AEOVSIL):
                                nvme_mi_resp[m][1] = data[j + k] | (nvme_mi_resp[m][1] << 8)
                            j += AEOVSIL
                            m += 1
    # "Configuration Get"
        elif self.LastOpcode == 0x04:            
            if self.LastCID == 0x01:
                # NVMe Managment Response
                nvme_mi_resp[1] = ["SFREQ",         NVMeMngResp & 0xF,                                                      "SMBus/I2C Frequency"]
            elif self.LastCID == 0x03:
                # NVMe Managment Response
                nvme_mi_resp[1] = ["MTUS",          NVMeMngResp & 0xFFFF,                                                   "MCTP Transmission Unit Size"]
            elif self.LastCID == 0x04:
                # NVMe Managment Response
                nvme_mi_resp[1] = ["AEELVER",       NVMeMngResp & 0xFF,                                                     "AE Enable List Version Number"]
                # Response Data                
                nvme_mi_resp[2] = ["NUMAES",        data[4],                                                                "Number of AE Supported Data Structures"] 
                nvme_mi_resp[3] = ["AESLVER",       data[5],                                                                "AE Supported List Version Number"]
                nvme_mi_resp[4] = ["AESTL",         data[6] | (data[7] << 8),                                               "AE Supported Total Length"]
                nvme_mi_resp[5] = ["AESLHL",        data[8],                                                                "AE Supported List Header Length"]
                j = 9
                m = 6
                for i in range(0, nvme_mi_resp[2][1]):
                    nvme_mi_resp[m] = ["AESL",      data[j],                                                                "AE Supported Length"]
                    nvme_mi_resp[m + 1] = ["AESI",      data[j + 1] | (data[j + 2] << 8),                                   "AE Supported Info"]
                    nvme_mi_resp[m + 2] = ["AESE",      bool((nvme_mi_resp[m + 1][1] >> 15) & 0x1),                         "       AE Supported Enable"]
                    nvme_mi_resp[m + 3] = ["AESI",      nvme_mi_resp[m + 1][1] & 0xFFFF,                                    "       AE Supported ID"]
                    j += 3
                    m += 4
    # "VPD Read",
        elif self.LastOpcode == 0x05:
            # Response Data
            nvme_mi_resp[1] = ["VD",                        0,                                                              "VPD Data"]
            def Eva(self):
                if self.SOM == 0:
                    for i in data[Offset: Offset + Len]:
                        nvme_mi_resp[1][1] = i | (nvme_mi_resp[1][1] << 8)
                else:
                    for i in data[16: Len]:
                        nvme_mi_resp[1][1] = i | (nvme_mi_resp[1][1] << 8)
    # "SES Receive",
        elif self.LastOpcode == 0x08:
            # NVMe Managment Response
            nvme_mi_resp[1]  = ["RDL",                      NVMeMngResp & 0xFFFF,                                           "Response"]
            # Response Data
            nvme_mi_resp[2] = ["RD",                        0,                                                              "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    nvme_mi_resp[2][1] = i | (nvme_mi_resp[2][1] << 8)
            else:
                for i in data[16: Len]:
                    nvme_mi_resp[2][1] = i | (nvme_mi_resp[2][1] << 8)
    # "MEB Read",
        elif self.LastOpcode == 0x0A:
            # Response Data
            nvme_mi_resp[1] = ["MD",                        0,                                                              "MEB Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    nvme_mi_resp[1][1] = i | (nvme_mi_resp[1][1] << 8)
            else:
                for i in data[16: Len]:
                    nvme_mi_resp[1][1] = i | (nvme_mi_resp[1][1] << 8)
    #  "Vendor Specific"
        elif self.LastOpcode > 0x0C:
            # DWORD 0 (Bytes: 16 - 19)
            # DWORD 1 (Bytes: 20 - 23)
            return
        
        return nvme_mi_resp

    def handle_response_nvme_mi_command(self, data, firstPacket, Offset):        
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data
        Payload.extend([0 for i in range(len(Payload), 4224)])
        nvme_mi_resp = self.handle_resp_nvme_mi_parser(Payload, Offset, len(data))
        NVMeMiStatus = NVME_MI_STATUS.get(nvme_mi_resp[0][1], 'Reserved')
        NvmeMiResp = {
            0 :[12, 4, [14, ['NVMe-MI Response', 'NVMe-MI Resp', 'MMR']]],
            1 :[],
        }
        
    # "Read NVMe-MI Data Structure"
        if self.LastOpcode == 0x00:
            NvmeMiResp[1] = [12, 4, [4, ['%s: %s | %s: %02X' % (nvme_mi_resp[0][2], NVMeMiStatus, nvme_mi_resp[1][2], nvme_mi_resp[1][1]), '%s: %s | %s: %02X' % (nvme_mi_resp[0][0], NVMeMiStatus, nvme_mi_resp[1][0], nvme_mi_resp[1][1]), '%s | %s' %(nvme_mi_resp[0][0], nvme_mi_resp[1][0]), 'CG 1']]]
            # Response Data
            if self.LastDytp == 0x00:   # NVM Subsystem Information
                NvmeMiResp[2] = [16, 4, [14, ['RDS: NVM Subsystem Information', 'RDS: 0', 'RDS']]]
                NvmeMiResp[3] = [16, 4, [4, ['%s: %02X | %s: %02X | %s: %02X | %s: %02X | %s: %02X' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1], nvme_mi_resp[3][2], nvme_mi_resp[3][1], nvme_mi_resp[4][2], nvme_mi_resp[4][1], nvme_mi_resp[5][2], nvme_mi_resp[5][1], nvme_mi_resp[6][2], nvme_mi_resp[6][1]), '%s: %02X | %s: %02X | %s: %02X | %s: %02X | %s: %02X' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1], nvme_mi_resp[3][0], nvme_mi_resp[3][1], nvme_mi_resp[4][0], nvme_mi_resp[4][1], nvme_mi_resp[5][0], nvme_mi_resp[5][1], nvme_mi_resp[6][0], nvme_mi_resp[6][1]), '%s|%s|%s|%s|%s' % (nvme_mi_resp[2][0], nvme_mi_resp[3][0], nvme_mi_resp[4][0], nvme_mi_resp[5][0], nvme_mi_resp[6][0]), 'RDS']]]
                NvmeMiResp[4] = [20, 28, [14, ['Reserved NVM Subsystem Information', 'RSVD RDS', 'R']]]
                NvmeMiResp[5] = [20, 28, [4, ['Reserved', 'RSVD', 'R']]]
            elif self.LastDytp == 0x01: # Port Information
                NvmeMiResp[2] = [16, 4, [14, ['RDS: Port Information', 'RDS: 1', 'RDS']]]
                NvmeMiResp[3] = [16, 4, [4, ['%s: %02X | %s: %02X ► %s: %r  %s: %r | %s: %04X' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1], nvme_mi_resp[3][2], nvme_mi_resp[3][1], nvme_mi_resp[4][2], nvme_mi_resp[4][1], nvme_mi_resp[5][2], nvme_mi_resp[5][1], nvme_mi_resp[6][2], nvme_mi_resp[6][1]), '%s: %02X | %s: %02X ► %s: %r  %s: %r | %s: %04X' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1], nvme_mi_resp[3][0], nvme_mi_resp[3][1], nvme_mi_resp[4][0], nvme_mi_resp[4][1], nvme_mi_resp[5][0], nvme_mi_resp[5][1], nvme_mi_resp[6][0], nvme_mi_resp[6][1]), '%s|%s ► %s %s|%s' % (nvme_mi_resp[2][0], nvme_mi_resp[3][0], nvme_mi_resp[4][0], nvme_mi_resp[5][0], nvme_mi_resp[6][0]), 'RDS']]]
                NvmeMiResp[4] = [20, 4, [14, ['RDS: Port Information', 'RDS: 1', 'RDS']]]
                NvmeMiResp[5] = [20, 4, [4, ['%s: %08X' % (nvme_mi_resp[7][2], nvme_mi_resp[7][1]), '%s %08X' % (nvme_mi_resp[7][0], nvme_mi_resp[7][1]), '%s' % nvme_mi_resp[7][0], 'RDS']]]
                if nvme_mi_resp[2][1] == 0x01: # PCIe Port Specific Data
                    NvmeMiResp[6] = [24, 4, [14, ['RDS: Port Information: PCIe Port', 'RDS: PCIe Port', 'RDS']]]
                    NvmeMiResp[7] = [24, 4, [4, ['%s %02X | %s %02X ► %s %r - %s %r - %s %r - %s %r - %s %r - %s %r | %s %02X | %s %02X' % 
                    (nvme_mi_resp[8][2], nvme_mi_resp[8][1], nvme_mi_resp[9][2], nvme_mi_resp[9][1], nvme_mi_resp[10][2], nvme_mi_resp[10][1], nvme_mi_resp[11][2], nvme_mi_resp[11][1], nvme_mi_resp[12][2], nvme_mi_resp[12][1], nvme_mi_resp[13][2], nvme_mi_resp[13][1], nvme_mi_resp[14][2], nvme_mi_resp[14][1], nvme_mi_resp[15][2], nvme_mi_resp[15][1], nvme_mi_resp[16][2], nvme_mi_resp[16][1], nvme_mi_resp[17][2], nvme_mi_resp[17][1]), '%s %02X | %s %02X ► %s %r - %s %r - %s %r - %s %r - %s %r - %s %r | %s %02X | %s %02X' % (nvme_mi_resp[8][0], nvme_mi_resp[8][1], nvme_mi_resp[9][0], nvme_mi_resp[9][1], nvme_mi_resp[10][0], nvme_mi_resp[10][1], nvme_mi_resp[11][0], nvme_mi_resp[11][1], nvme_mi_resp[12][0], nvme_mi_resp[12][1], nvme_mi_resp[13][0], nvme_mi_resp[13][1], nvme_mi_resp[14][0], nvme_mi_resp[14][1], nvme_mi_resp[15][0], nvme_mi_resp[15][1], nvme_mi_resp[16][0], nvme_mi_resp[16][1], nvme_mi_resp[17][0], nvme_mi_resp[17][1]), '%s|%s ► %s,%s,%s,%s,%s,%s|%s|%s' % (nvme_mi_resp[8][0], nvme_mi_resp[9][0], nvme_mi_resp[10][0], nvme_mi_resp[11][0], nvme_mi_resp[12][0], nvme_mi_resp[13][0], nvme_mi_resp[14][0], nvme_mi_resp[15][0], nvme_mi_resp[16][0], nvme_mi_resp[17][0]), 'RDS']]]
                    NvmeMiResp[8] = [28, 4, [14, ['RDS: Port Information: PCIe Port', 'RDS: PCIe Port', 'RDS']]]
                    NvmeMiResp[9] = [28, 4, [4, ['%s %02X | %s %02X' % (nvme_mi_resp[18][2], nvme_mi_resp[18][1], nvme_mi_resp[19][2], nvme_mi_resp[19][1]), '%s %02X | %s %02X' % (nvme_mi_resp[18][0], nvme_mi_resp[18][1], nvme_mi_resp[19][0], nvme_mi_resp[19][1]), '%s|%s' % (nvme_mi_resp[18][0], nvme_mi_resp[19][0]), 'RDS']]]
                    NvmeMiResp[10] = [32, 16, [14, ['Reserved Read NVMe-MI Data Structure', 'RSVD RDS', 'R']]]
                    NvmeMiResp[11] = [32, 16, [4, ['Reserved', 'RSVD', 'R']]]
                elif nvme_mi_resp[2][1] == 0x02:   # 2-Wire Port Specific Data
                    NvmeMiResp[6] = [24, 4, [14, ['RDS: Port Information: 2-Wire Port', 'RDS: 2-Wire Port', 'RDS']]]
                    NvmeMiResp[7] = [24, 4, [4, ['%s %02X | %s %02X | %s %02X | %s %02X ► %s %r → %s %02X' % (nvme_mi_resp[8][2], nvme_mi_resp[8][1], nvme_mi_resp[9][2], nvme_mi_resp[9][1], nvme_mi_resp[10][2], nvme_mi_resp[10][1], nvme_mi_resp[11][2], nvme_mi_resp[11][1], nvme_mi_resp[12][2], nvme_mi_resp[12][1], nvme_mi_resp[13][2], nvme_mi_resp[13][1]), '%s %02X | %s %02X | %s %02X | %s %02X ► %s %r → %s %02X' % (nvme_mi_resp[8][0], nvme_mi_resp[8][1], nvme_mi_resp[9][0], nvme_mi_resp[9][1], nvme_mi_resp[10][0], nvme_mi_resp[10][1], nvme_mi_resp[11][0], nvme_mi_resp[11][1], nvme_mi_resp[12][0], nvme_mi_resp[12][1], nvme_mi_resp[13][0], nvme_mi_resp[13][1]), '%s|%s|%s|%s|%s|%s' % (nvme_mi_resp[8][0], nvme_mi_resp[9][0], nvme_mi_resp[10][0], nvme_mi_resp[11][0], nvme_mi_resp[12][0], nvme_mi_resp[13][0]), 'RDS']]]
                    NvmeMiResp[8] = [28, 4, [14, ['RDS: Port Information: 2-Wire Port', 'RDS: 2-Wire Port', 'RDS']]]
                    NvmeMiResp[9] = [28, 4, [4, ['%s %02X' % (nvme_mi_resp[14][2], nvme_mi_resp[14][1]), '%s %02X' % (nvme_mi_resp[14][0], nvme_mi_resp[14][1]), '%s' % nvme_mi_resp[14][0], 'RDS']]]
                    NvmeMiResp[10] = [32, 16, [14, ['Reserved Read NVMe-MI Data Structure', 'RSVD RDS', 'R']]]
                    NvmeMiResp[11] = [32, 16, [4, ['Reserved', 'RSVD', 'R']]]
                else:   # Inactive or Reserved
                    NvmeMiResp[6] = [24, 24, [14, ['Reserved Read NVMe-MI Data Structure', 'RSVD RDS', 'R']]]
                    NvmeMiResp[7] = [24, 24, [4, ['Reserved', 'RSVD', 'R']]]
            elif self.LastDytp == 0x02: # Controller List
                NvmeMiResp[2] = [16, 2, [14, ['RDS: Controller List', 'RDS: 2', 'RDS']]]
                NvmeMiResp[3] = [16, 2, [4, ['%s: %04X' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1]), '%s: %04X' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1]), '%s' % nvme_mi_resp[2][0], 'RDS']]]
                j = 4
                for i in range(0, nvme_mi_resp[2][1]):
                    NvmeMiResp[j] = [j + 14, 2, [14, ['RDS: Controller %d' % i, 'RDS: CTRL %d' % i, 'CTRL%d' % i]]]
                    NvmeMiResp[j + 1] = [j + 14, 2, [4, ['%s: %04X' % (nvme_mi_resp[i + 3][2], nvme_mi_resp[i + 3][1]), '%s: %04X' % (nvme_mi_resp[i + 3][0], nvme_mi_resp[i + 3][1]), '%s' % (nvme_mi_resp[i + 3][0]), 'RDS']]]
                    j += 2
            elif self.LastDytp == 0x03: # Controller Information
                NvmeMiResp[2] = [16, 4, [14, ['RDS: Controller Information', 'RDS: 3', 'RDS']]]
                NvmeMiResp[3] = [16, 4, [4, ['%s: %02X' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1]), '%s: %02X' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1]), '%s' % (nvme_mi_resp[2][0]), 'RDS']]]
                NvmeMiResp[4] = [20, 4, [14, ['RDS: Controller Information', 'RDS: 3', 'RDS']]]
                NvmeMiResp[5] = [20, 4, [4, ['%s: %02X ► %s: %r | %s: %04X ► %s: %02X → %s: %02X → %s: %02X' % (nvme_mi_resp[3][2], nvme_mi_resp[3][1], nvme_mi_resp[4][2], nvme_mi_resp[4][1], nvme_mi_resp[5][2], nvme_mi_resp[5][1], nvme_mi_resp[6][2], nvme_mi_resp[6][1], nvme_mi_resp[7][2], nvme_mi_resp[7][1], nvme_mi_resp[8][2], nvme_mi_resp[8][1]), '%s: %02X ► %s: %r | %s: %04X ► %s: %02X → %s: %02X → %s: %02X' % (nvme_mi_resp[3][0], nvme_mi_resp[3][1], nvme_mi_resp[4][0], nvme_mi_resp[4][1], nvme_mi_resp[5][0], nvme_mi_resp[5][1], nvme_mi_resp[6][0], nvme_mi_resp[6][1], nvme_mi_resp[7][0], nvme_mi_resp[7][1], nvme_mi_resp[8][0], nvme_mi_resp[8][1]), '%s ► %s|%s ► %s,%s,%s' % (nvme_mi_resp[3][0], nvme_mi_resp[4][0], nvme_mi_resp[5][0], nvme_mi_resp[6][0], nvme_mi_resp[7][0], nvme_mi_resp[8][0]), 'RDS']]]
                NvmeMiResp[6] = [24, 4, [14, ['RDS: Controller Information', 'RDS: 3', 'RDS']]]
                NvmeMiResp[7] = [24, 4, [4, ['%s: %04X | %s: %04X' % (nvme_mi_resp[9][2], nvme_mi_resp[9][1], nvme_mi_resp[10][2], nvme_mi_resp[10][1]), '%s: %04X | %s: %04X' % (nvme_mi_resp[9][0], nvme_mi_resp[9][1], nvme_mi_resp[10][0], nvme_mi_resp[10][1]), '%s|%s' % (nvme_mi_resp[9][0], nvme_mi_resp[10][0]), 'RDS']]]
                NvmeMiResp[8] = [28, 4, [14, ['RDS: Controller Information', 'RDS: 3', 'RDS']]]
                NvmeMiResp[9] = [28, 4, [4, ['%s: %04X | %s: %04X' % (nvme_mi_resp[11][2], nvme_mi_resp[11][1], nvme_mi_resp[12][2], nvme_mi_resp[12][1]), '%s: %04X | %s: %04X' % ( nvme_mi_resp[11][0], nvme_mi_resp[11][1], nvme_mi_resp[12][0], nvme_mi_resp[12][1]), '%s|%s' % (nvme_mi_resp[11][0], nvme_mi_resp[12][0]), 'RDS']]]
                NvmeMiResp[10] = [32, 4, [14, ['RDS: Controller Information', 'RDS: 3', 'RDS']]]
                NvmeMiResp[11] = [32, 4, [4, ['%s: %02X' % (nvme_mi_resp[13][2], nvme_mi_resp[13][1]), '%s: %02X' % (nvme_mi_resp[13][0], nvme_mi_resp[13][1]), '%s' % (nvme_mi_resp[13][0]), 'RDS']]]
                NvmeMiResp[12] = [36, 12, [14, ['Reserved RDS Controller Information', 'RSVD RDS', 'R']]]
                NvmeMiResp[13] = [36, 12, [4, ['Reserved', 'RSVD', 'R']]]
            elif self.LastDytp == 0x04: # Optionally Supported Command List       
                NvmeMiResp[2] = [16, 2, [14, ['RDS: Supported Command List', 'RDS: 4', 'RDS']]]
                NvmeMiResp[3] = [16, 2, [4, ['%s: %04X' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1]), '%s: %04X' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1]), '%s' % nvme_mi_resp[2][0], 'RDS']]]
                j = 4
                k = 3
                for i in range(0,nvme_mi_resp[2][1]):
                    NvmeMiResp[j] = [j + 14, 2, [14, ['RDS: Supported Command List', 'RDS: 4', 'RDS']]]
                    NvmeMiResp[j + 1] = [j + 14, 2, [4, ['%s: %04X ► %s: %01X | %s: %02X' % (nvme_mi_resp[k][2], nvme_mi_resp[k][1], nvme_mi_resp[k + 1][2], nvme_mi_resp[k + 1][1], nvme_mi_resp[k + 2][2], nvme_mi_resp[k + 2][1]), '%s: %04X | %s: %01X | %s: %02X' % (nvme_mi_resp[k][0], nvme_mi_resp[k][1], nvme_mi_resp[k + 1][0], nvme_mi_resp[k + 1][1], nvme_mi_resp[k + 2][0], nvme_mi_resp[k + 2][1]), '%s|%s|%s' % (nvme_mi_resp[k][0], nvme_mi_resp[k + 1][0], nvme_mi_resp[k + 2][0]), 'RDS']]]
                    j += 2
                    k += 3
            elif self.LastDytp == 0x05: # Management Endpoint Buffer Command Support List
                NvmeMiResp[2] = [16, 2, [14, ['RDS: Management Endpoint Buffer Command Support List', 'RDS: 5', 'RDS']]]
                NvmeMiResp[3] = [16, 2, [4, ['%s: %04X' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1]), '%s: %04X' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1]), '%s' % nvme_mi_resp[2][0], 'RDS']]]
                j = 4
                k = 3
                for i in range(0,nvme_mi_resp[2][1]):
                    NvmeMiResp[j] = [j + 14, 2, [14, ['RDS: Management Endpoint Buffer Command Support List', 'RDS: 5', 'RDS']]]
                    NvmeMiResp[j + 1] = [j + 14, 2, [4, ['%s: %04X ► %s: %01X | %s: %02X' % (nvme_mi_resp[k][2], nvme_mi_resp[k][1], nvme_mi_resp[k + 1][2], nvme_mi_resp[k + 1][1], nvme_mi_resp[k + 2][2], nvme_mi_resp[k + 2][1]), '%s: %04X | %s: %01X | %s: %02X' % (nvme_mi_resp[k][0], nvme_mi_resp[k][1], nvme_mi_resp[k + 1][0], nvme_mi_resp[k + 1][1], nvme_mi_resp[k + 2][0], nvme_mi_resp[k + 2][1]), '%s|%s|%s' % (nvme_mi_resp[k][0], nvme_mi_resp[k + 1][0], nvme_mi_resp[k + 2][0]), 'RDS']]]
                    j += 2
                    k += 3
    # "NVM Subsystem Health Status Poll",
        elif self.LastOpcode == 0x01:
            NvmeMiResp[1] = [12, 4, [4, ['%s: %s' % (nvme_mi_resp[0][2], NVMeMiStatus), '%s: %s' % (nvme_mi_resp[0][0], NVMeMiStatus), '%s' %(nvme_mi_resp[0][0]), 'NMR']]]
            # Response Data
            NvmeMiResp[2] = [16, 4, [14, ['NVM Subsystem Health Status Poll', 'NVM SHSP', 'NSHS']]]
            NvmeMiResp[3] = [20, 4, [4, ['%s: %02X ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r | %s: %02X | %s: %02X | %s: %02X' % (nvme_mi_resp[1][2], nvme_mi_resp[1][1], nvme_mi_resp[2][2], nvme_mi_resp[2][1], nvme_mi_resp[3][2], nvme_mi_resp[3][1], nvme_mi_resp[4][2], nvme_mi_resp[4][1], nvme_mi_resp[5][2], nvme_mi_resp[5][1], nvme_mi_resp[6][2], nvme_mi_resp[6][1], nvme_mi_resp[7][2], nvme_mi_resp[7][1], nvme_mi_resp[8][2], nvme_mi_resp[8][1], nvme_mi_resp[9][2], nvme_mi_resp[9][1], nvme_mi_resp[10][2], nvme_mi_resp[10][1], nvme_mi_resp[11][2], nvme_mi_resp[11][1]), '%s: %02X ► %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d | %s: %02X | %s: %02X | %s: %02X' % (nvme_mi_resp[1][0], nvme_mi_resp[1][1], nvme_mi_resp[2][0], nvme_mi_resp[2][1], nvme_mi_resp[3][0], nvme_mi_resp[3][1], nvme_mi_resp[4][0], nvme_mi_resp[4][1], nvme_mi_resp[5][0], nvme_mi_resp[5][1], nvme_mi_resp[6][0], nvme_mi_resp[6][1], nvme_mi_resp[7][0], nvme_mi_resp[7][1], nvme_mi_resp[8][0], nvme_mi_resp[8][1], nvme_mi_resp[9][0], nvme_mi_resp[9][1], nvme_mi_resp[10][0], nvme_mi_resp[10][1], nvme_mi_resp[11][0], nvme_mi_resp[11][1]), '%s ► %s→%s→%s→%s→%s→%s→%s | %s | %s | %s' % (nvme_mi_resp[1][0], nvme_mi_resp[2][0], nvme_mi_resp[3][0], nvme_mi_resp[4][0], nvme_mi_resp[5][0], nvme_mi_resp[6][0], nvme_mi_resp[7][0], nvme_mi_resp[8][0], nvme_mi_resp[9][0], nvme_mi_resp[10][0], nvme_mi_resp[11][0]), 'NSHS']]]
            NvmeMiResp[4] = [24, 4, [14, ['NVM Subsystem Health Status Poll', 'NVM SHSP', 'NSHS']]]
            NvmeMiResp[5] = [28, 4, [4, ['%s: %04X ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r' % (nvme_mi_resp[12][2], nvme_mi_resp[12][1], nvme_mi_resp[13][2], nvme_mi_resp[13][1], nvme_mi_resp[14][2], nvme_mi_resp[14][1], nvme_mi_resp[15][2], nvme_mi_resp[15][1], nvme_mi_resp[16][2], nvme_mi_resp[16][1], nvme_mi_resp[17][2], nvme_mi_resp[17][1], nvme_mi_resp[18][2], nvme_mi_resp[18][1], nvme_mi_resp[19][2], nvme_mi_resp[19][1], nvme_mi_resp[20][2], nvme_mi_resp[20][1], nvme_mi_resp[21][2], nvme_mi_resp[21][1], nvme_mi_resp[22][2], nvme_mi_resp[22][1], nvme_mi_resp[23][2], nvme_mi_resp[23][1], nvme_mi_resp[24][2], nvme_mi_resp[24][1], nvme_mi_resp[25][2], nvme_mi_resp[25][1]), '%s: %04X ► %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d' % (nvme_mi_resp[12][0], nvme_mi_resp[12][1], nvme_mi_resp[13][0], nvme_mi_resp[13][1], nvme_mi_resp[14][0], nvme_mi_resp[14][1], nvme_mi_resp[15][0], nvme_mi_resp[15][1], nvme_mi_resp[16][0], nvme_mi_resp[16][1], nvme_mi_resp[17][0], nvme_mi_resp[17][1], nvme_mi_resp[18][0], nvme_mi_resp[18][1], nvme_mi_resp[19][0], nvme_mi_resp[19][1], nvme_mi_resp[20][0], nvme_mi_resp[20][1], nvme_mi_resp[21][0], nvme_mi_resp[21][1], nvme_mi_resp[22][0], nvme_mi_resp[22][1], nvme_mi_resp[23][0], nvme_mi_resp[23][1], nvme_mi_resp[24][0], nvme_mi_resp[24][1], nvme_mi_resp[25][0], nvme_mi_resp[25][1]), '%s ► %s→%s→%s→%s→%s→%s→%s→%s→%s→%s→%s→%s→%s' % (nvme_mi_resp[12][0], nvme_mi_resp[13][0], nvme_mi_resp[14][0], nvme_mi_resp[15][0], nvme_mi_resp[16][0], nvme_mi_resp[17][0], nvme_mi_resp[18][0], nvme_mi_resp[19][0], nvme_mi_resp[20][0], nvme_mi_resp[21][0], nvme_mi_resp[22][0], nvme_mi_resp[23][0], nvme_mi_resp[24][0], nvme_mi_resp[25][0]), 'NSHS']]]
    # "Controller Health Status Poll",
        elif self.LastOpcode == 0x02:
            # NVMe Managment Response
            NvmeMiResp[1] = [12, 4, [4, ['%s: %s | %s: %02X' % (nvme_mi_resp[0][2], NVMeMiStatus, nvme_mi_resp[1][2], nvme_mi_resp[1][1]), '%s: %s | %s: %02X' % (nvme_mi_resp[0][0], NVMeMiStatus, nvme_mi_resp[1][0], nvme_mi_resp[1][1]), '%s | %s' %(nvme_mi_resp[0][0], nvme_mi_resp[1][0]), 'CG 1']]]
            # Response Data
            NvmeMiResp[2] = [16, 4, [14, ['Controller Health Status Poll', 'Ctrll Health', 'CHSP']]]
            NvmeMiResp[3] = [16, 4, [4, ['%s: %04X | %s: %04X ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %d → %s: %r → %s: %r' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1], nvme_mi_resp[3][2], nvme_mi_resp[3][1], nvme_mi_resp[4][2], nvme_mi_resp[4][1], nvme_mi_resp[5][2], nvme_mi_resp[5][1], nvme_mi_resp[6][2], nvme_mi_resp[6][1], nvme_mi_resp[7][2], nvme_mi_resp[7][1], nvme_mi_resp[8][2], nvme_mi_resp[8][1], nvme_mi_resp[9][2], nvme_mi_resp[9][1], nvme_mi_resp[10][2], nvme_mi_resp[10][1], nvme_mi_resp[11][2], nvme_mi_resp[11][1]), '%s: %04X | %s: %04X ► %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1], nvme_mi_resp[3][0], nvme_mi_resp[3][1], nvme_mi_resp[4][0], nvme_mi_resp[4][1], nvme_mi_resp[5][0], nvme_mi_resp[5][1], nvme_mi_resp[6][0], nvme_mi_resp[6][1], nvme_mi_resp[7][0], nvme_mi_resp[7][1], nvme_mi_resp[8][0], nvme_mi_resp[8][1], nvme_mi_resp[9][0], nvme_mi_resp[9][1], nvme_mi_resp[10][0], nvme_mi_resp[10][1], nvme_mi_resp[11][0], nvme_mi_resp[11][1]), '%s|%s ► %s→%s→%s→%s→%s→%s→%s→%s' % (nvme_mi_resp[2][0], nvme_mi_resp[3][0], nvme_mi_resp[4][0], nvme_mi_resp[5][0], nvme_mi_resp[6][0], nvme_mi_resp[7][0], nvme_mi_resp[8][0], nvme_mi_resp[9][0], nvme_mi_resp[10][0], nvme_mi_resp[11][0]), 'CHSP']]]
            NvmeMiResp[4] = [20, 4, [14, ['Controller Health Status Poll', 'Ctrll Health', 'CHSP']]]
            NvmeMiResp[5] = [20, 4, [4, ['%s: %04X | %s: %02X | %s: %02X' % (nvme_mi_resp[12][2], nvme_mi_resp[12][1], nvme_mi_resp[13][2], nvme_mi_resp[13][1], nvme_mi_resp[14][2], nvme_mi_resp[14][1]), '%s: %04X | %s: %02X | %s: %02X' % (nvme_mi_resp[12][0], nvme_mi_resp[12][1], nvme_mi_resp[13][0], nvme_mi_resp[13][1], nvme_mi_resp[14][0], nvme_mi_resp[14][1]), '%s|%s|%s|' % (nvme_mi_resp[12][0], nvme_mi_resp[13][0], nvme_mi_resp[14][0], ), 'CHSP']]]
            NvmeMiResp[6] = [24, 4, [14, ['Controller Health Status Poll', 'Ctrll Health', 'CHSP']]]
            NvmeMiResp[7] = [24, 4, [4, ['%s: %02X ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r |%s: %04X ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r' % (nvme_mi_resp[15][2], nvme_mi_resp[15][1], nvme_mi_resp[16][2], nvme_mi_resp[16][1], nvme_mi_resp[17][2], nvme_mi_resp[17][1], nvme_mi_resp[18][2], nvme_mi_resp[18][1], nvme_mi_resp[19][2], nvme_mi_resp[19][1], nvme_mi_resp[20][2], nvme_mi_resp[20][1], nvme_mi_resp[21][2], nvme_mi_resp[21][1], nvme_mi_resp[22][2], nvme_mi_resp[22][1], nvme_mi_resp[23][2], nvme_mi_resp[23][1], nvme_mi_resp[24][2], nvme_mi_resp[24][1], nvme_mi_resp[25][2], nvme_mi_resp[25][1], nvme_mi_resp[26][2], nvme_mi_resp[26][1], nvme_mi_resp[27][2], nvme_mi_resp[27][1], nvme_mi_resp[28][2], nvme_mi_resp[28][1], nvme_mi_resp[29][2], nvme_mi_resp[29][1], nvme_mi_resp[30][2], nvme_mi_resp[30][1], nvme_mi_resp[31][2], nvme_mi_resp[31][1], nvme_mi_resp[32][2], nvme_mi_resp[32][1], nvme_mi_resp[33][2], nvme_mi_resp[33][1], nvme_mi_resp[34][2], nvme_mi_resp[34][1], nvme_mi_resp[35][2], nvme_mi_resp[35][1], nvme_mi_resp[36][2], nvme_mi_resp[36][1]), '%s: %02X ► %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d |%s: %04X ► %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d → %s: %d' % (nvme_mi_resp[15][0], nvme_mi_resp[15][1], nvme_mi_resp[16][0], nvme_mi_resp[16][1], nvme_mi_resp[17][0], nvme_mi_resp[17][1], nvme_mi_resp[18][0], nvme_mi_resp[18][1], nvme_mi_resp[19][0], nvme_mi_resp[19][1], nvme_mi_resp[20][0], nvme_mi_resp[20][1], nvme_mi_resp[21][0], nvme_mi_resp[21][1], nvme_mi_resp[22][0], nvme_mi_resp[22][1], nvme_mi_resp[23][0], nvme_mi_resp[23][1], nvme_mi_resp[24][0], nvme_mi_resp[24][1], nvme_mi_resp[25][0], nvme_mi_resp[25][1], nvme_mi_resp[26][0], nvme_mi_resp[26][1], nvme_mi_resp[27][0], nvme_mi_resp[27][1], nvme_mi_resp[28][0], nvme_mi_resp[28][1], nvme_mi_resp[29][0], nvme_mi_resp[29][1], nvme_mi_resp[30][0], nvme_mi_resp[30][1], nvme_mi_resp[31][0], nvme_mi_resp[31][1], nvme_mi_resp[32][0], nvme_mi_resp[32][1], nvme_mi_resp[33][0], nvme_mi_resp[33][1], nvme_mi_resp[34][0], nvme_mi_resp[34][1], nvme_mi_resp[35][0], nvme_mi_resp[35][1], nvme_mi_resp[36][0], nvme_mi_resp[36][1]), '%s ► %s→%s→%s→%s→%s→%s→%s | %s ► %s→%s→%s→%s→%s→%s→%s→%s→%s→%s→%s→%s→%s' % (nvme_mi_resp[15][0], nvme_mi_resp[16][0], nvme_mi_resp[17][0], nvme_mi_resp[18][0], nvme_mi_resp[19][0], nvme_mi_resp[20][0], nvme_mi_resp[21][0], nvme_mi_resp[22][0], nvme_mi_resp[23][0], nvme_mi_resp[24][0], nvme_mi_resp[25][0], nvme_mi_resp[26][0], nvme_mi_resp[27][0], nvme_mi_resp[28][0], nvme_mi_resp[29][0], nvme_mi_resp[30][0], nvme_mi_resp[31][0], nvme_mi_resp[32][0], nvme_mi_resp[33][0], nvme_mi_resp[34][0], nvme_mi_resp[35][0], nvme_mi_resp[36][0]), 'NSHS']]]
            NvmeMiResp[8] = [28, 4, [14, ['Reserved Controller Health Status Poll', 'RSVD CHSP', 'CHSP']]]
            NvmeMiResp[9] = [28, 4, [4, ['Reserved: 00 00 00 00', 'RSVD: 00 00 00 00', 'RSVD']]]
   # "Configuration Set"
        elif self.LastOpcode == 0x03:
            NvmeMiResp[1] = [12, 4, [4, ['%s: %s' % (nvme_mi_resp[0][2], NVMeMiStatus), '%s: %s' % (nvme_mi_resp[0][0], NVMeMiStatus), '%s' %(nvme_mi_resp[0][0]), 'NMR']]]
            if self.LastCID == 0x04:
                # Response Data
                # if the AE Occurrence List Overflow = ‘1’, then the AE Occurrence List data structure = AE Occurrence List Header and shall not contain an AE Occurrence List Body.
                ## AE Occurrence List Header
                NvmeMiResp[2] = [16, 7, [14, ['AE Occurrence List', 'AEO List', 'AEOL']]]
                NvmeMiResp[3] = [16, 7, [4, ['%s: %02X | %s: %02X | %s: %06X ► %s: %06X → %s: %r | %s: %02X | %s: %02X ► %s: %02X → %s: %01X ' % (nvme_mi_resp[1][2], nvme_mi_resp[1][1], nvme_mi_resp[2][2], nvme_mi_resp[2][1], nvme_mi_resp[3][2], nvme_mi_resp[3][1], nvme_mi_resp[4][2], nvme_mi_resp[4][1], nvme_mi_resp[5][2], nvme_mi_resp[5][1], nvme_mi_resp[6][2], nvme_mi_resp[6][1], nvme_mi_resp[7][2], nvme_mi_resp[7][1], nvme_mi_resp[8][2], nvme_mi_resp[8][1], nvme_mi_resp[9][2], nvme_mi_resp[9][1]), '%s: %02X | %s: %02X | %s: %06X ► %s: %06X → %s: %r | %s: %02X | %s: %02X ► %s: %02X → %s: %01X ' % (nvme_mi_resp[1][0], nvme_mi_resp[1][1], nvme_mi_resp[2][0], nvme_mi_resp[2][1], nvme_mi_resp[3][0], nvme_mi_resp[3][1], nvme_mi_resp[4][0], nvme_mi_resp[4][1], nvme_mi_resp[5][0], nvme_mi_resp[5][1], nvme_mi_resp[6][0], nvme_mi_resp[6][1], nvme_mi_resp[7][0], nvme_mi_resp[7][1], nvme_mi_resp[8][0], nvme_mi_resp[8][1], nvme_mi_resp[9][0], nvme_mi_resp[9][1]), '%s|%s|%s ► %s→%s|%s|%s ► %s→%s' % (nvme_mi_resp[1][0], nvme_mi_resp[2][0], nvme_mi_resp[3][0], nvme_mi_resp[4][0], nvme_mi_resp[5][0], nvme_mi_resp[6][0], nvme_mi_resp[7][0], nvme_mi_resp[8][0], nvme_mi_resp[9][0]), 'AEOL']]]
                if nvme_mi_resp[4][1] == 0:
                    # AE Occurence N
                    j = 23
                    m = 10
                    k = 4
                    for i in range(0, nvme_mi_resp[1][1]):
                        NvmeMiResp[k] = [j, 9, [14, ['AE Occurrence %d' % i, 'AE Ocurr %d' % i, 'AEO%d'%i]]]
                        NvmeMiResp[k + 1] = [j, 9, [4, ['%s: %02X | %s: %02X | %s: %02X | %s: %02X | %s: %08X | %s: %02X ► %s: %01X' % (nvme_mi_resp[m][2], nvme_mi_resp[m][1], nvme_mi_resp[m + 1][2], nvme_mi_resp[m + 1][1], nvme_mi_resp[m + 2][2], nvme_mi_resp[m + 2][1], nvme_mi_resp[m + 3][2], nvme_mi_resp[m + 3][1], nvme_mi_resp[m + 4][2], nvme_mi_resp[m + 4][1], nvme_mi_resp[m + 5][2], nvme_mi_resp[m + 5][1], nvme_mi_resp[m + 6][2], nvme_mi_resp[m + 6][1]), '%s: %02X | %s: %02X | %s: %02X | %s: %02X | %s: %08X | %s: %02X ► %s: %01X' % (nvme_mi_resp[m][0], nvme_mi_resp[m][1], nvme_mi_resp[m + 1][0], nvme_mi_resp[m + 1][1], nvme_mi_resp[m + 2][0], nvme_mi_resp[m + 2][1], nvme_mi_resp[m + 3][0], nvme_mi_resp[m + 3][1], nvme_mi_resp[m + 4][0], nvme_mi_resp[m + 4][1], nvme_mi_resp[m + 5][0], nvme_mi_resp[m + 5][1], nvme_mi_resp[m + 6][0], nvme_mi_resp[m + 6][1]), '%s|%s|%s|%s|%s|%s ► %s' % (nvme_mi_resp[m][0], nvme_mi_resp[m + 1][0], nvme_mi_resp[m + 2][0], nvme_mi_resp[m + 3][0], nvme_mi_resp[m + 4][0], nvme_mi_resp[m + 5][0], nvme_mi_resp[m + 6][0]), 'CHSP']]]
                        AEOSIL, AEOVSIL = nvme_mi_resp[m + 1][1], nvme_mi_resp[m + 2][1]
                        j += 9
                        m += 7
                        k += 2
                        # AE Occurence Specific Info
                        if AEOSIL != 0:
                            NvmeMiResp[k] = [j, AEOSIL, [14, ['AE Occurence Specific Info %d' % i, 'AE Ocurr SI %d' % i, 'AEOSI%d'%i]]]
                            NvmeMiResp[k + 1] = [j, AEOSIL, [4, ['%s: %X' % (nvme_mi_resp[m][2], nvme_mi_resp[m][1]), '%s: %X' % (nvme_mi_resp[m][0], nvme_mi_resp[m][1]), '%s' % (nvme_mi_resp[m][0]), 'AEOSI']]]
                            j += AEOSIL
                            m += 1
                            k += 2
                        # AE Occurence Vendor Specific Info
                        if AEOVSIL != 0:
                            NvmeMiResp[k] = [j, AEOVSIL, [14, ['AE Occurence Vendor Specific Info %d' % i, 'AE Ocurr VSI %d' % i, 'AEOVSI%d'%i]]]
                            NvmeMiResp[k + 1] = [j, AEOVSIL, [4, ['%s: %X' % (nvme_mi_resp[m][2], nvme_mi_resp[m][1]), '%s: %X' % (nvme_mi_resp[m][0], nvme_mi_resp[m][1]), '%s' % (nvme_mi_resp[m][0]), 'AEOVSIL']]]
                            j += AEOVSIL
                            m += 1
                            k += 2
    # "Configuration Get"
        elif self.LastOpcode == 0x04:            
            if self.LastCID == 0x01:
                NvmeMiResp[1] = [12, 4, [4, ['%s: %s | %s: %02X' % (nvme_mi_resp[0][2], NVMeMiStatus, nvme_mi_resp[1][2], nvme_mi_resp[1][1]), '%s: %s | %s: %02X' % (nvme_mi_resp[0][0], NVMeMiStatus, nvme_mi_resp[1][0], nvme_mi_resp[1][1]), '%s | %s' %(nvme_mi_resp[0][0], nvme_mi_resp[1][0]), 'CG 1']]]
            elif self.LastCID == 0x03:
                NvmeMiResp[1] = [12, 4, [4, ['%s: %s | %s: %02X' % (nvme_mi_resp[0][2], NVMeMiStatus, nvme_mi_resp[1][2], nvme_mi_resp[1][1]), '%s: %s | %s: %02X' % (nvme_mi_resp[0][0], NVMeMiStatus, nvme_mi_resp[1][0], nvme_mi_resp[1][1]), '%s | %s' %(nvme_mi_resp[0][0], nvme_mi_resp[1][0]), 'CG 1']]]
            elif self.LastCID == 0x04:
                NvmeMiResp[1] = [12, 4, [4, ['%s: %s | %s: %02X' % (nvme_mi_resp[0][2], NVMeMiStatus, nvme_mi_resp[1][2], nvme_mi_resp[1][1]), '%s: %s | %s: %02X' % (nvme_mi_resp[0][0], NVMeMiStatus, nvme_mi_resp[1][0], nvme_mi_resp[1][1]), '%s | %s' %(nvme_mi_resp[0][0], nvme_mi_resp[1][0]), 'CG 1']]]
                # Response Data                
                NvmeMiResp[2] = [16, 5, [14, ['CG: Asynchronous Event', 'CG 4', 'CG']]]
                NvmeMiResp[3] = [16, 5, [4, ['%s: %02X | %s: %02X | %s: %04X | %s: %02X' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1], nvme_mi_resp[3][2], nvme_mi_resp[3][1], nvme_mi_resp[4][2], nvme_mi_resp[4][1], nvme_mi_resp[5][2], nvme_mi_resp[5][1]), '%s: %02X | %s: %02X | %s: %04X | %s: %02X' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1], nvme_mi_resp[3][0], nvme_mi_resp[3][1], nvme_mi_resp[4][0], nvme_mi_resp[4][1], nvme_mi_resp[5][0], nvme_mi_resp[5][1]), '%s | %s | %s | %s' %(nvme_mi_resp[2][0], nvme_mi_resp[3][0], nvme_mi_resp[4][0], nvme_mi_resp[5][0]), 'AES']]]
                j = 21
                m = 6
                k = 4
                for i in range(0, nvme_mi_resp[2][1]):
                    NvmeMiResp[k] = [j, 3, [14, ['AE Supported %d' % i, 'AE Supp %d' % i, 'AES %d' % i]]]
                    NvmeMiResp[k + 1] = [j, 3, [4, ['%s: %02X | %s: %04X | %s: %r | %s: %02X' % (nvme_mi_resp[m][2], nvme_mi_resp[m][1], nvme_mi_resp[m + 1][2], nvme_mi_resp[m + 1][1], nvme_mi_resp[m + 2][2], nvme_mi_resp[m + 2][1], nvme_mi_resp[m + 3][2], nvme_mi_resp[m + 3][1]), '%s: %02X | %s: %04X | %s: %r | %s: %02X' % (nvme_mi_resp[m][0], nvme_mi_resp[m][1], nvme_mi_resp[m + 1][0], nvme_mi_resp[m + 1][1], nvme_mi_resp[m + 2][0], nvme_mi_resp[m + 2][1], nvme_mi_resp[m + 3][0], nvme_mi_resp[m + 3][1]), '%s | %s | %s | %s' %(nvme_mi_resp[m][0], nvme_mi_resp[m + 1][0], nvme_mi_resp[m + 2][0], nvme_mi_resp[m + 3][0]), 'AES']]]
                    m += 4
                    j += 3
                    k += 2
            else:
                NvmeMiResp[1] = [12, 4, [4, ['%s: %s' % (nvme_mi_resp[0][2], NVMeMiStatus), '%s: %s' % (nvme_mi_resp[0][0], NVMeMiStatus), '%s' %(nvme_mi_resp[0][0]), 'NMR']]]
    # "VPD Read",
        elif self.LastOpcode == 0x05:
            NvmeMiResp[1] = [12, 4, [4, ['%s: %s' % (nvme_mi_resp[0][2], NVMeMiStatus), '%s: %s' % (nvme_mi_resp[0][0], NVMeMiStatus), '%s' %(nvme_mi_resp[0][0]), 'NMR']]]
            # Response Data
            NvmeMiResp[2] = [16, 255, [14, ['VPD Read', 'VPD R', 'VPD']]]
            NvmeMiResp[3] = [16, 255, [4, ['%s: %X' % (nvme_mi_resp[1][2], nvme_mi_resp[1][1]), '%s: %X' % (nvme_mi_resp[1][0], nvme_mi_resp[1][1]), '%s' %(nvme_mi_resp[1][0]), 'VPD']]]
    # "SES Receive",
        elif self.LastOpcode == 0x08:
            NvmeMiResp[1] = [12, 4, [4, ['%s: %s | %s: %02X' % (nvme_mi_resp[0][2], NVMeMiStatus, nvme_mi_resp[1][2], nvme_mi_resp[1][1]), '%s: %s | %s: %02X' % (nvme_mi_resp[0][0], NVMeMiStatus, nvme_mi_resp[1][0], nvme_mi_resp[1][1]), '%s | %s' %(nvme_mi_resp[0][0], nvme_mi_resp[1][0]), 'CG 1']]]
            # Response Data
            NvmeMiResp[2] = [16, 255, [14, ['SES Receive', 'SES R', 'SES']]]
            NvmeMiResp[3] = [16, 255, [4, ['%s: %X' % (nvme_mi_resp[2][2], nvme_mi_resp[2][1]), '%s: %X' % (nvme_mi_resp[2][0], nvme_mi_resp[2][1]), '%s' %(nvme_mi_resp[2][0]), 'SES']]]
    # "MEB Read",
        elif self.LastOpcode == 0x0A:
            NvmeMiResp[1] = [12, 4, [4, ['%s: %s' % (nvme_mi_resp[0][2], NVMeMiStatus), '%s: %s' % (nvme_mi_resp[0][0], NVMeMiStatus), '%s' %(nvme_mi_resp[0][0]), 'NMR']]]
            # Response Data
            NvmeMiResp[2] = [16, 255, [14, ['MEB Read', 'MEB R', 'MEB']]]
            NvmeMiResp[3] = [16, 255, [4, ['%s: %X' % (nvme_mi_resp[1][2], nvme_mi_resp[1][1]), '%s: %X' % (nvme_mi_resp[1][0], nvme_mi_resp[1][1]), '%s' %(nvme_mi_resp[1][0]), 'MEB']]]
        elif self.LastOpcode in [0x06, 0x07, 0x09, 0x0B, 0x0C]:
            NvmeMiResp[1] = [12, 4, [4, ['%s: %s' % (nvme_mi_resp[0][2], NVMeMiStatus), '%s: %s' % (nvme_mi_resp[0][0], NVMeMiStatus), '%s' %(nvme_mi_resp[0][0]), 'NMR']]]
    #  "Vendor Specific"
        elif self.LastOpcode > 0x0C:
            # DWORD 0 (Bytes: 16 - 19)
            # DWORD 1 (Bytes: 20 - 23)
            return

        Cnt = firstPacket
        for Idx, value in list(NvmeMiResp.items())[::2]:
            if NvmeMiResp[Idx][0] >= (Offset + firstPacket) or NvmeMiResp[Idx][1] > Offset :
                if (Cnt + NvmeMiResp[Idx][1]) < (firstPacket + len(data)):
                    self.put(self.packets[Cnt][0], self.packets[Cnt + NvmeMiResp[Idx][1] - 1][1], self.out_ann, NvmeMiResp[Idx][2])
                    self.put(self.packets[Cnt][0], self.packets[Cnt + NvmeMiResp[Idx][1] - 1][1], self.out_ann, NvmeMiResp[Idx + 1][2])
                    Cnt += NvmeMiResp[Idx][1]
                else:
                    self.put(self.packets[Cnt][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, NvmeMiResp[Idx][2])
                    self.put(self.packets[Cnt][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, NvmeMiResp[Idx + 1][2])
                    Cnt += len(data)

    def handle_resp_nvme_admin_command_parser(self, data, Offset, Len):
        admin_resp = {
            0 :             ["STA",                     data[0],                                                                    "Status"],
            # CQE DW 0
            1 :             ["DW0",                     data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24),               "CQE DWORD 0"],
            # CQE DW1
            2 :             ["SQHD",                    data[8] | (data[9] << 8),                                                   "SQ Head Pointer"],
            3 :             ["SQID",                    data[10] | (data[11] << 8),                                                 "SQ Identifier"],
            # CQE DW3
            4 :             ["CID",                     data[12] | (data[13] << 8),                                                 "Command Identifier"],
            5 :             ["P",                       bool(data[14] & 0x01),                                                      "Phase Tag"],
            6 :             ["STATUS",                  (data[14] | (data[15] << 8)) >> 1,                                                 "Status"],
            7 :             ["DNR",                     bool((data[15]) & 0x80),                                  "Do Not Retry"],
            8 :             ["M",                       bool((data[15]) & 0x40),                                  "More"],
            9 :             ["CRD",                     ((data[14] | (data[15] << 8)) >> 12) & 0x03,                                "Command Retry Delay"],
            10 :            ["SCT",                     ((data[14] | (data[15] << 8)) >> 9) & 0x07,                                 "Status Code Type"],
            11 :            ["SC",                      ((data[14] | (data[15] << 8)) >> 1) & 0xFF,                                 "Status Code"],
        }
        data[0] = 1
        # Response Data
    # "Get Log Page",
        if self.LastOpcode == 0x02:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
    # "Identify",
        elif self.LastOpcode == 0x06:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
    # "Set Features",
        elif self.LastOpcode == 0x09:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Get Features",
        elif self.LastOpcode == 0x0A:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Namespace Management",
        elif self.LastOpcode == 0x0D:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Firmware Commit",
        elif self.LastOpcode == 0x10:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Firmware Image Download",
        elif self.LastOpcode == 0x11:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Device Self-Test",
        elif self.LastOpcode == 0x14:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Namespace attachment",
        elif self.LastOpcode == 0x15:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Virtualization Management",
        elif self.LastOpcode == 0x1C:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Capacity Management",
        elif self.LastOpcode == 0x20:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Lockdown",
        elif self.LastOpcode == 0x24:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Clear Exported NVM Resource Configuration",
        elif self.LastOpcode == 0x28:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Create Exported NVM Subsystem",
        elif self.LastOpcode == 0x2A:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Manage Exported NVM Subsystem",
        elif self.LastOpcode == 0x2D:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Manage Exported Namespace",
        elif self.LastOpcode == 0x31:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Manage Exported Port",
        elif self.LastOpcode == 0x35:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Format NVM",
        elif self.LastOpcode == 0x80:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Security Send",
        elif self.LastOpcode == 0x81:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Security Receive",
        elif self.LastOpcode == 0x82:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Sanitize",
        elif self.LastOpcode == 0x84:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Get LBA Status",
        elif self.LastOpcode == 0x86:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
    # "Sanitize Namespace",
        elif self.LastOpcode == 0x8C:
            admin_resp[12] = ["RD",                        0,                                          "Response Data"]
            if self.SOM == 0:
                for i in data[Offset: Offset + Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)
            else:
                for i in data[16: Len]:
                    admin_resp[12][1] = i | (admin_resp[12][1] << 8)        
        return admin_resp

    def handle_response_nvme_admin_command(self, data, firstPacket, Offset):
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data
        Payload.extend([0 for i in range(len(Payload), 4224)])
        admin_resp = self.handle_resp_nvme_admin_command_parser(Payload, Offset, len(data))
        AdminDataPrint = {
            0 :[14, ['NVMe-MI Response', 'NVMe-MI Resp', 'MIR']],
            1 :[4, ['%s: %02X' % (admin_resp[0][2], admin_resp[0][1]), '%s: %02X' % (admin_resp[0][0], admin_resp[0][1]), '%s' % (admin_resp[0][0]), 'NMR']],
            2 :[14, ['DWORD 0', 'DW 0', 'D0']],
            3 :[4, ['%s: %08X' % (admin_resp[1][2], admin_resp[1][1]), '%s: %08X' % (admin_resp[1][0], admin_resp[1][1]), '%s' % (admin_resp[1][0]), 'DW0']],
            4 :[14, ['DWORD 1', 'DW 1', 'D1']],
            5 :[4, ['%s: %04X | %s: %04X' % (admin_resp[2][2], admin_resp[2][1], admin_resp[3][2], admin_resp[3][1]), '%s: %04X | %s: %04X' % (admin_resp[2][0], admin_resp[2][1], admin_resp[3][0], admin_resp[3][1]), '%s | %s' % (admin_resp[2][0], admin_resp[3][0]), 'DW1']],
            6 :[14, ['DWORD 3', 'DW 3', 'D3']],
            7 :[4, ['%s: %04X | %s: %r | %s ► %s: %r → %s: %r → %s: %01X → %s: %01X → %s: %02X' % (admin_resp[4][2], admin_resp[4][1], admin_resp[5][2], admin_resp[5][1], admin_resp[6][2], admin_resp[7][2], admin_resp[7][1], admin_resp[8][2], admin_resp[8][1], admin_resp[9][2], admin_resp[9][1], admin_resp[10][2], admin_resp[10][1], admin_resp[11][2], admin_resp[11][1]),'%s: %04X | %s: %r | %s ► %s: %r → %s: %r → %s: %01X → %s: %01X → %s: %02X' % (admin_resp[4][0], admin_resp[4][1], admin_resp[5][0], admin_resp[5][1], admin_resp[6][0], admin_resp[7][0], admin_resp[7][1], admin_resp[8][0], admin_resp[8][1], admin_resp[9][0], admin_resp[9][1], admin_resp[10][0], admin_resp[10][1], admin_resp[11][0], admin_resp[11][1]),'%s | %s | %s ► %s → %s → %s → %s → %s' % (admin_resp[4][0], admin_resp[5][0], admin_resp[6][0], admin_resp[7][0], admin_resp[8][0], admin_resp[9][0], admin_resp[10][0], admin_resp[11][0]),'DW3']],
            8 :[14, ['Response Data', 'Res Data', 'RQ']],
            9 :[4, ['%s: %X' % (admin_resp[12][2], admin_resp[12][1]), '%s: %X' % (admin_resp[12][0], admin_resp[12][1]), '%s' % (admin_resp[12][0]), 'RD']],
        }
        
        # #NVMeMiStatus = NVME_MI_STATUS.get(admin_resp[0][1], 'Reserveed')
        
    # # "Get Log Page",
        # if self.LastOpcode == 0x02:
            # self.put(self.packets[28][0], self.packets[-6][1], self.out_ann, AdminDataPrint[8])
            # self.put(self.packets[28][0], self.packets[-6][1], self.out_ann, AdminDataPrint[9])
    # # "Identify",
        # elif self.LastOpcode == 0x06:
            # self.put(self.packets[28][0], self.packets[-6][1], self.out_ann, [14, ['Response Data', 'Res Data', 'RQ']])
            # self.put(self.packets[28][0], self.packets[-6][1], self.out_ann, [4, ['%s: %X' % (admin_resp[12][2], admin_resp[12][1]), '%s: %X' % (admin_resp[12][0], admin_resp[12][1]), '%s' % (admin_resp[12][0]), 'RD']])

        j = (Offset/4) * 2 # (Offset / 4) is equal to dword N requested and *2  is the table position.
        if j >= 8:
            self.put(self.packets[firstPacket][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, AdminDataPrint[8])
            self.put(self.packets[firstPacket][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, AdminDataPrint[9])
        else:
            for i in range(firstPacket, firstPacket + len(data) - 4, 4):
                if j == 8:
                    i -= 4
                    break
                else:
                    self.put(self.packets[i][0], self.packets[i + 3][1], self.out_ann, AdminDataPrint[j])
                    self.put(self.packets[i][0], self.packets[i + 3][1], self.out_ann, AdminDataPrint[j + 1])
                    j += 2
            i = firstPacket if i == 0 else i + 4
            self.put(self.packets[i][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, AdminDataPrint[j])
            self.put(self.packets[i][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, AdminDataPrint[j + 1])

    def handle_response_pcie_command(self):
        return
        
    def handle_response_asynchronous_event(self):
        return

    def handle_Message_Integrity_Check(self):
        self.put(self.packets[-5][0], self.packets[-2][1], self.out_ann, [7, ['Message Intigrity Check', 'Mes Int Check', 'MIC']])
        MIC = self.packets[-5][3] | (self.packets[-4][3] << 8) | (self.packets[-3][3] << 16) | (self.packets[-2][3] << 24)
        self.put(self.packets[-5][0], self.packets[-2][1], self.out_ann, [4, 
        ['Messages Integrity Check ▸ %08X' % MIC,                  'MIC: %08X' % MIC, 
        '%08X' % MIC,                               'MIC']])

    def handle_PEC(self):
        self.put(self.packets[-1][0], self.packets[-1][1], self.out_ann, [7, ['Packet Error Checking', 'Pck Error Check', 'PEC']])
        PEC = self.packets[-1][3]
        self.put(self.packets[-1][0], self.packets[-1][1], self.out_ann, [4, 
        ['Packet Error Checking ▸ %02X' % PEC,                  'PEC: %02X' % PEC, 
        '%02X' % PEC,                               'PEC']])

    def put_payload_bytes(self):
        # NVMe MI Req 0x1D -> 0x3A
        if self.packets[0][3] == 0x3A and self.error == 0:
            self.handle_smbus()
            self.handle_mctp()
            if self.SOM == 1 and self.EOM == 1:
                self.handle_mi()
                Data = [self.packets[j][3] for j in range(12, (len(self.packets) - 5))]
                self.handle_mi_req_or_resp(Data, 12, 0)
                #self.handle_mi_payload(Data,12)
                self.handle_Message_Integrity_Check()
            if self.SOM == 1 and self.EOM == 0:
                self.handle_mi()
                Data = [self.packets[j][3] for j in range(12, (len(self.packets) - 1))]
                self.handle_mi_req_or_resp(Data, 12, 0)
                self.offset = len(Data)
                #self.handle_mi_payload(Data,12)
            if self.SOM == 0 and self.EOM == 0:
                Data = [self.packets[j][3] for j in range(8, (len(self.packets) - 1))]
                self.handle_mi_req_or_resp(Data, 8, self.offset)
                self.offset += len(Data)                
                #self.handle_mi_payload(Data,12)
            if self.SOM == 0 and self.EOM == 1:
                Data = [self.packets[j][3] for j in range(8, (len(self.packets) - 5))]
                self.handle_mi_req_or_resp(Data, 8, self.offset)
                self.offset = 0
                #self.handle_mi_payload(Data,12)
                self.handle_Message_Integrity_Check()
            self.handle_PEC()
        # NVMe MI Res 0x10 -> 0x10
        if self.packets[0][3] == 0x20 and self.error == 0:
            self.handle_smbus()
            self.handle_mctp()
            if self.SOM == 1 and self.EOM == 1:
                self.handle_mi()
                Data = [self.packets[j][3] for j in range(12, (len(self.packets) - 5))]
                self.handle_mi_req_or_resp(Data, 12, 0)
                # self.handle_mi_payload(Data[4:-5],12)
                self.handle_Message_Integrity_Check()
            if self.SOM == 1 and self.EOM == 0:
                self.handle_mi()
                Data = [self.packets[j][3] for j in range(12, (len(self.packets) - 1))]
                self.handle_mi_req_or_resp(Data, 12, 0)
                self.offset = len(Data)
                # self.handle_mi_payload(Data[4:-1],12)
            if self.SOM == 0 and self.EOM == 0:
                Data = [self.packets[j][3] for j in range(8, (len(self.packets) - 1))]
                self.handle_mi_payload_response(Data, 8, self.offset)
                self.offset += len(Data)
                # self.handle_mi_payload(Data[:-1],8)
            if self.SOM == 0 and self.EOM == 1:
                Data = [self.packets[j][3] for j in range(8, (len(self.packets) - 5))]
                self.handle_mi_payload_response(Data, 8, self.offset)
                self.offset = 0
                # self.handle_mi_payload(Data[:-5],8)
                self.handle_Message_Integrity_Check()
            self.handle_PEC()
        # BMC Req 0x6A -> 0xD4
        if self.packets[0][3] == 0xD4 and self.error == 0:
            self.handle_request_BMC()
        # BMC Res 0x6A -> 0xD5
        if self.packets[0][3] == 0xD5 and self.error == 1:
            self.handle_response_BMC_CC()
        # VPD Req 0x53 -> 0xA6
        if self.packets[0][3] == 0xA6 and self.error == 0:
            self.handle_request_VPD()
        # VPD Res 0x53 -> 0xA7
        if self.packets[0][3] == 0xA7 and self.error == 1:
            self.handle_response_VPD()       
    
    def handle_request_VPD(self):
        SMBusAddr = self.packets[0][3]
        Offset = self.packets[1][3]
        self.put(self.packets[0][0], self.packets[1][1], self.out_ann, [3, 
        ['SMBusAddr: %02X | Offset: %02X' % (SMBusAddr, Offset), 
        '%02X | %02X' % (SMBusAddr, Offset), 
        'SMBusAddr|Offset', 
        'CC']])
        self.put(self.packets[0][0], self.packets[1][1], self.out_ann, [12, ['VPD Read w/offset: %02X' % Offset, 'VPD Read', 'VPD']])

    def Type_Length_Byte(self, Field):
        # Type/Length Byte Format
            # Type Code
        TCODE = (Field >> 6) & 0x03
            # Number Of Data Bytes
        NDB =  (Field & 0x1F)
        
        return NDB
        
    def handle_resp_vpd_parser(self, data):
        vpd_data = {
            0 : ['SBA',                 data[0],                        "SMBus Address"],
        }
        VPD = 0
        for i in range(1, len(data)):
            VPD      = data[i] | (VPD << 8)
                
        Offset = 1
        # Common Header
        vpd_data[0] = ["IPMIVER",                 data[Offset],               "IPMI Format Version Number"],
        vpd_data[1] = ["IUAOFF",                  data[Offset + 1],           "Internal Use Area Starting Offset"],
        vpd_data[2] = ["CIAOFF",                  data[Offset + 2],           "Chassis Info Area Starting Offset"],
        vpd_data[3] = ["BIAOFF",                  data[Offset + 3],           "Board Info Area Starting Offset"],
        vpd_data[4] = ["PIAOFF",                  data[Offset + 4],           "Product Info Area Starting Offset"],
        vpd_data[5] = ["MRIOFF",                  data[Offset + 5],           "MultiRecord Info Area Starting Offset"],
        vpd_data[6] = ["BFC",                     data[Offset + 6],           "Boot Failure Code"],
        vpd_data[7] = ["CHCHK",                   data[Offset + 7],           "Common Header Checksum"],
        
        idx = 8
        # Internal Use Area
        if (vpd_data[1][1]  * 8) != 0:
            IUA = 0
        
        # Chassis Info Area
        if (vpd_data[2][1]  * 8) != 0:
            CIA = 0
        
        # Board Info Area
        if (vpd_data[3][1]  * 8) != 0:
            BIA = 0
        
        # Product Info Area
        if (vpd_data[4][1] * 8) != 0:
            vpd_data[idx] = ["IPMIVER",             data[Offset + 8],           'IPMI Format Version Number'],
            vpd_data[idx + 1] = ["PALEN",               data[Offset + 9],           'Product Info Area Length'],
            vpd_data[idx + 2] = ["LCODE",              data[Offset + 10],          'Language Code'],
            vpd_data[idx + 3] = ["MNTL",               data[Offset + 11],          'Manufacturer Name Type/Length'],
            vpd_data[idx + 4] = ["MNAME",              0,                          'Manufacturer Name'],
            vpd_data[idx + 5] = ["PNTL",               0,                          'Product Name Type/Length'],
            vpd_data[idx + 6] = ["PNAME",              0,                          'Product Name'],
            vpd_data[idx + 7] = ["PPMNNTL",            0,                          'Product Part/Model Number Type/Length'],
            vpd_data[idx + 8] = ["PPMN",               0,                          'Product Part/Model Number'],
            vpd_data[idx + 9] = ["PVTL",               0,                          'Product Version Type/Length'],
            vpd_data[idx + 10] = ["PVER",               0,                          'Product Version'],
            vpd_data[idx + 11] = ["PSNTL",              0,                          'Product Serial Number Type/Length'],
            vpd_data[idx + 12] = ["PSN",                0,                          'Product Serial Number'],
            vpd_data[idx + 13] = ["ATTL",               0,                          'Asset Tag Type/Length'],
            vpd_data[idx + 14] = ["AT",                 0,                          'Asset Tag'],
            vpd_data[idx + 15] = ["FFITL",              0,                          'FRU File ID Type/Length'],
            vpd_data[idx + 16] = ["FFI",                0,                          'FRU File ID'],
            vpd_data[idx + 17] = ["CPIA",               0,                          'Custom Product Info Area'],
            vpd_data[idx + 18] = ["EOR",                0,                          'End of Record'],
            vpd_data[idx + 19] = ["Pad",                0,                          'ZerosPadding'],
            vpd_data[idx + 20] = ["PICHK",              0,                          'Product Info Area'],
            
            def ManufacturerName (self):
                Offset += 12
                Bytes = self.Type_Length_Byte(vpd_data[idx + 3][1]) + Offset
                MNAME = 0
                MNAME2 = ''
                for j in range(Offset, Bytes):
                    MNAME = data[j] | (MNAME << 8)
                    MNAME2 = MNAME2 + "".join(chr(int(data[j])))
                vpd_data[idx + 4][1] = MNAME2
                Offset = Bytes

            def ProductName (self):
                vpd_data[idx + 5][1] = data[Offset][3]
                Offset += 1
                Bytes = self.Type_Length_Byte(vpd_data[idx + 5][1]) + Offset
                PNAME = 0
                PNAME2 = ''
                for j in range(Offset, Bytes):
                    PNAME = data[j] |(PNAME << 8)
                    PNAME2 = PNAME2 + "".join(chr(int(data[j])))
                vpd_data[idx + 6][1] = PNAME2
                Offset = Bytes            

            def ProductPartModelNumber (self):
                vpd_data[idx + 7][1] = data[Offset][3]
                Offset += 1
                Bytes = self.Type_Length_Byte(vpd_data[idx + 7][1]) + Offset
                PPMN = 0
                PPMN2 = ''
                for j in range(Offset, Bytes):
                    PPMN = data[j] |(PPMN << 8)
                    PPMN2 = PPMN2 + "".join(chr(int(data[j])))
                vpd_data[idx + 8][1] = PPMN2
                Offset = Bytes

            def ProductVersion (self):
                vpd_data[idx + 9][1] = data[Offset][3]
                Offset += 1
                Bytes = self.Type_Length_Byte(vpd_data[idx + 9][1]) + Offset
                PVER = 0
                PVER2 = ''
                for j in range(Offset, Bytes):
                    PVER = data[j] |(PVER << 8)
                    PVER2 = PVER2 + "".join(chr(int(data[j])))
                vpd_data[idx + 10][1] = PVER2
                Offset = Bytes            

            def ProductSerialNumber (self):
                vpd_data[idx + 11][1] = data[Offset][3]
                Offset += 1
                Bytes = self.Type_Length_Byte(vpd_data[idx + 11][1]) + Offset
                PSN = 0
                PSN2 = ''
                for j in range(Offset, Bytes):
                    PSN = data[j] |(PSN << 8)
                    PSN2 = PSN2 + "".join(chr(int(data[j])))
                vpd_data[idx + 12][1] = PSN2
                Offset = Bytes

            def AssetTag (self):
                vpd_data[idx + 13][1] = data[Offset][3]
                Offset += 1
                Bytes = self.Type_Length_Byte(vpd_data[idx + 13][1]) + Offset
                Bytes = Bytes + 1 if vpd_data[idx + 13][1] == 0 else Bytes
                AT = 0
                AT2 = ''
                for j in range(Offset, Bytes):
                    AT = data[j] |(AT << 8)
                    AT2 = AT2 + "".join(chr(int(data[j])))
                vpd_data[idx + 14][1] = AT2
                Offset = Bytes            

            def FRUFileID (self):
                vpd_data[idx + 15][1] = data[Offset][3]
                Offset += 1
                Bytes = self.Type_Length_Byte(vpd_data[idx + 15][1]) + Offset
                Bytes = Bytes + 1 if vpd_data[idx + 15][1] == 0 else Bytes
                FFI = 0
                for j in range(Offset, Bytes):
                    FFI = data[j] |(FFI << 8)
                vpd_data[idx + 16][1] = FFI
                Offset = Bytes

            vpd_data[idx + 17][1] = data[Offset][3]
            vpd_data[idx + 18][1] = data[Offset + 1][3]
            
            def ZerosPadding (self):
                Offset += 2
                BytPadd = Offset % 8
                Pad = 0
                for j in range(Offset, (8 - BytPadd) + Offset): 
                    Pad = data[j] | (Pad << 8)
                vpd_data[idx + 19][1] = PNAME2
                Offset += (8 - BytPadd)
                
            vpd_data[idx + 20][1] = data[Offset][3]
            
            idx += 21
            
        # MultiRecord Info Area 
        if (vpd_data[5][1]  * 8) != 0:
            Offset = (vpd_data[5][1]  * 8) + 1
            # NVMe MultiRecord Area
            vpd_data[idx] = ["RTI",                                 data[Offset],                         "Record Type Identifier"],
            vpd_data[idx + 1] = ["RFMT",                           data[Offset + 1],                     "Record Format"],
            vpd_data[idx + 2] = ["LREC",                           bool((vpd_data[52][1] >> 7) & 0x1),   "        Last Record"],
            vpd_data[idx + 3] = ["RVER",                           (vpd_data[52][1] & 0x7F),             "        Record Version"],
            vpd_data[idx + 4] = ["RLEN",                           data[Offset + 2],                     "Record Length"],
            vpd_data[idx + 5] = ["RCSUM",                          data[Offset + 3],                     "Record Checksum"],
            vpd_data[idx + 6] = ["HSUM",                           data[Offset + 4],                     "Header Checksum"],
            vpd_data[idx + 7] = ["NMAVN",                          data[Offset + 5],                     "NMVe Multirecord Area Version Number"],
            vpd_data[idx + 8] = ["FF",                             data[Offset + 6],                     "Form Factor"],
            vpd_data[idx + 9] = ["Inf",                            0,                                    "        Interface"],
            vpd_data[idx + 10] = ["Desc",                           0,                                    "        Description"],
            vpd_data[idx + 11] = ["I1P8PSR",                        data[Offset + 13],                    "Initial 1.8V Power Supply Requirements"],
            vpd_data[idx + 12] = ["M1P8PSR",                        data[Offset + 14],                    "Maximum 1.8V Power Supply Requirements"],
            vpd_data[idx + 13] = ["I3P3PSR",                        data[Offset + 15],                    "Initial 3.3V Power Supply Requirements"],
            vpd_data[idx + 14] = ["M3P3PSR",                        data[Offset + 16],                    "Maximum 3.3V Power Supply Requirements"],
            vpd_data[idx + 15] = ["M3P3APSR",                       data[Offset + 18],                    "Maximum 3.3V Aux Power Supply Requirements"],
            vpd_data[idx + 16] = ["I5PSR",                          data[Offset + 19],                    "Initial 5V Power Supply Requirements"],
            vpd_data[idx + 17] = ["M5PSR",                          data[Offset + 20],                    "Maximum 5V Power Supply Requirements"],
            vpd_data[idx + 18] = ["I12PSR",                         data[Offset + 21],                    "Initial 12V Power Supply Requirements"],
            vpd_data[idx + 19] = ["M12PSR",                         data[Offset + 22],                    "Maximum 12V Power Supply Requirements"],
            vpd_data[idx + 20] = ["MTL",                            data[Offset + 23],                    "Maximum Thermal Load"],
            vpd_data[idx + 21] = ["TNVMCAP",                        0,                                    "Total NVM Capacity"],
            
            for j in range(Offset + 24, Offset + 37):
                vpd_data[idx + 21][1] = data[j]  | (vpd_data[idx + 21][1] << 8)
            vpd_data[idx + 9][1], vpd_data[idx + 10][1] = UPD_FORM_FACTOR[FF]
            Offset += 64
            idx += 22

        # NVMe PCIe Port MultiRecord Area
            vpd_data[idx] = ["RTI",                              data[Offset],                       "Record Type Identifier"],
            vpd_data[idx + 1] = ["RFMT",                             data[Offset + 1],                   "Record Format"],
            vpd_data[idx + 2] = ["LREC",                             bool((vpd_data[52][1] >> 7) & 0x1), "       Last Record"],
            vpd_data[idx + 3] = ["RVER",                             (vpd_data[52][1] & 0x7F),           "       Record Version"],
            vpd_data[idx + 4] = ["RLEN",                             data[Offset + 2],                   "Record Length"],
            vpd_data[idx + 5] = ["RCSUM",                            data[Offset + 3],                   "Record Checksum"],
            vpd_data[idx + 6] = ["HSUM",                             data[Offset + 4],                   "Header Checksum"],
            vpd_data[idx + 7] = ["NPCIEPMAVN",                       data[Offset + 5],                   "NVMe PCIe Port MultiRecord Area Version Number"],
            vpd_data[idx + 8] = ["PCIEPN",                           data[Offset + 6],                   "PCIe Port Number"],
            vpd_data[idx + 9] = ["PINFO",                            data[Offset + 7],                   "Port Information"],
            vpd_data[idx + 10] = ["PCIELS",                           data[Offset + 8],                   "PCIe Link Speed"],
            vpd_data[idx + 11] = ["PCIEMLW",                          data[Offset + 9],                   "PCIe Maximum Link Width"],
            vpd_data[idx + 12] = ["MCTPS",                            data[Offset + 10],                  "MCTP Support"],
            vpd_data[idx + 13] = ["RCCAP",                            data[Offset + 11],                  "Ref Clk Capability"],
            vpd_data[idx + 14] = ["PORTID",                           data[Offset + 12],                  "Port Identifier"],
            PCIEMLWmap = PCIE_MAX_LINK_WIDTH.get(vpd_data[idx + 11][1], 'Reserved')
            Offset += 16
            idx += 15

        # Topology MultiRecord Area
            vpd_data[idx] = ["RTI",                                 data[Offset],                       "Record Type Identifier"],
            vpd_data[idx + 1] = ["RFMT",                             data[Offset + 1],                   "Record Format"],
            vpd_data[idx + 2] = ["LREC",                             bool((vpd_data[67][1] >> 7) & 0x1), "       Last Record"],
            vpd_data[idx + 3] = ["RVER",                             (vpd_data[67][1] & 0x7F),           "       Record Version"],
            vpd_data[idx + 4] = ["RLEN",                             data[Offset + 2],                   "Record Length"],
            vpd_data[idx + 5] = ["RCSUM",                            data[Offset + 3],                   "Record Checksum"],
            vpd_data[idx + 6] = ["HSUM",                             data[Offset + 4],                   "Header Checksum"],
            vpd_data[idx + 7] = ["VNUM",                             data[Offset + 5],                   "Version Number"],
            vpd_data[idx + 8] = ["ELEMC",                            data[Offset + 7],                   "Element Count"],
            Offset += 8
            IdxElemc = idx + 9
            for j in range(0, vpd_data[idx + 8][1]):
                vpd_data[IdxElemc] =    ["TYP",                          data[Offset],                       "Type"],
                vpd_data[IdxElemc + 1] = ["REV",                          data[Offset + 1],                   "Revision"],
                vpd_data[IdxElemc + 2] = ["LEN",                          data[Offset + 2],                   "Length"],

                TSINFO = 0
                for k in range(3, vpd_data[IdxElemc + 2][1]):
                    TSINFO  = data[Offset + k] | (TSINFO << 8)
                
                if vpd_data[IdxElemc][1] == 1:    # Extended Element Descriptor
                    vpd_data[IdxElemc + 3] = ["EXTC",                          TSINFO,                   "Extended Content"],
                    Offset += k
                    IdxElemc += 4
                elif vpd_data[IdxElemc][1] == 2:  # Upstream Connector Element Descriptor
                    vpd_data[IdxElemc + 3] =  ["FF",                  data[Offset + 3],                   "Format Factor"],
                    vpd_data[IdxElemc + 4] =  ["Inf",                 0,                                  "        Interface"],
                    vpd_data[IdxElemc + 5] =  ["Desc",                0,                                  "        Description"],
                    vpd_data[IdxElemc + 6] =  ["LPTR",                data[Offset + 4],                   "Label Pointer"],
                    vpd_data[IdxElemc + 7] =  ["MAXAPWR",             data[Offset + 7],                   "Maximum Auxiliary Power"],
                    vpd_data[IdxElemc + 8] =  ["MAXPWR",              data[Offset + 9] | (data[Offset + 8] << 8),"Maximum Power"],
                    vpd_data[IdxElemc + 9] =  ["UPDC",                data[Offset + 10],                  "Upstream Port Descriptor Count"],
                    vpd_data[IdxElemc + 3][1], vpd_data[81][1] = UPD_FORM_FACTOR[FF]
                    IdxUDL = IdxElemc + 10
                    UPDOffset = Offset + 11
                    for l in range(0, vpd_data[IdxElemc + 9][1]):   # Upstream Port Descriptor List
                        vpd_data[IdxUDL] =  ["TYP",       data[UPDOffset],                    "Type"],
                        vpd_data[IdxUDL + 1] =  ["LEN",       data[UPDOffset + 1],                "Length"],
                        if data[UPDOffset] == 0:
                            vpd_data[IdxUDL + 2] =  ["CNT",       data[UPDOffset + 2],                "Count"],
                            IdxUDL2W = IdxUDL + 3
                            UPDOfst2W = UPDOffset + 3
                            for m in range(0,vpd_data[IdxUDL + 2][1]):
                                vpd_data[IdxUDL2W + m] =  ["2WP",       data[UPDOfst2W + m],                "2-Wire Pointer"],
                            IdxUDL += (m + 3)
                            UPDOffset += (m + 3)
                        elif data[UPDOffset] == 1:
                            vpd_data[IdxUDL + 2] =  ["SL",          data[UPDOffset + 2],                "Starting Lane"],
                            vpd_data[IdxUDL + 3] =  ["EL",          data[UPDOffset + 3],                "Ending Lane"],
                            vpd_data[IdxUDL + 4] =  ["PCIEPTR",     data[UPDOffset + 4],                "PCIe Pointer"],
                            vpd_data[IdxUDL + 5] =  ["DPORT",       data[UPDOffset + 5],                "Destination Port"],
                            IdxUDL += 6
                            UPDOffset += 6
                    IdxElemc += IdxUDL
                    Offset += UPDOffset
                elif vpd_data[IdxElemc][1] == 3:  # Expansion Connector Element 
                    vpd_data[IdxElemc + 3] =  ["FF",                    data[Offset + 3],                   "Format Factor"],
                    vpd_data[IdxElemc + 4] =  ["Inf",                   0,                                  "        Interface"],
                    vpd_data[IdxElemc + 5] =  ["Desc",                  0,                                  "        Description"],
                    vpd_data[IdxElemc + 6] =  ["LPTR",                  data[Offset + 4],                   "Label Pointer"],
                    vpd_data[IdxElemc + 7] =  ["ECPDC",                 data[Offset + 5],                   "Expansion Connector Port Descriptor Count"],
                    IdxECP = IdxElemc + 8
                    ECPOfst = Offset + 6
                    for l in range(0, vpd_data[IdxElemc + 7][1]): # Expansion Connector Port Descriptor
                        vpd_data[IdxECP] = ["TYP",                  data[ECPOfst],                  "Type"],
                        vpd_data[IdxECP + 1] = ["LEN",                  data[ECPOfst + 1],                  "Length"],
                        vpd_data[IdxECP + 2] = ["SL",                   data[ECPOfst + 2],                  "Starting Lane"],
                        vpd_data[IdxECP + 3] = ["EL",                   data[ECPOfst + 3],                  "Ending Lane"],
                        IdxECP += 4
                        ECPOfst += 4
                    IdxElemc += IdxECP
                    Offset += ECPOfst
                elif vpd_data[IdxElemc][1] == 4:  # Label Element Descriptor
                    vpd_data[IdxElemc + 3] = ["TSINFO",                          TSINFO,                   "Type-Specific Information"],
                    Offset += k
                    IdxElemc += 4
                elif vpd_data[IdxElemc][1] == 5:  # 2-Wire Mux Element Descriptor
                    vpd_data[IdxElemc + 3] = ["TSINFO",                          TSINFO,                   "Type-Specific Information"],
                    Offset += k
                    IdxElemc += 4
                elif vpd_data[IdxElemc][1] == 6:  # PCIe Switch Element Descriptor
                    vpd_data[IdxElemc + 3] = ["TSINFO",                          TSINFO,                   "Type-Specific Information"],
                    Offset += k
                    IdxElemc += 4
                elif vpd_data[IdxElemc][1] == 7:  # NVM Subsystem Element Descriptor
                    vpd_data[IdxElemc + 3] = ["TSINFO",                          TSINFO,                   "Type-Specific Information"],
                    Offset += k
                    IdxElemc += 4
                elif vpd_data[IdxElemc][1] == 8:  # FRU Information Device Element Descriptor
                    vpd_data[IdxElemc + 3] = ["TSINFO",                          TSINFO,                   "Type-Specific Information"],
                    Offset += k
                    IdxElemc += 4
                elif vpd_data[IdxElemc][1] > 240: # Vendor specific
                    vpd_data[IdxElemc + 3] = ["TSINFO",                          TSINFO,                   "Type-Specific Information"],
                    Offset += k
                    IdxElemc += 4
                TYPMap = ELEMENT_DESCRIPTOR_TYPE.get(TYP, 'Reserveed')
            idx += IdxElemc

    def handle_response_VPD(self):
        SMBusAddr = self.packets[0][3]
        VPD = 0
        for i in range(1, 257):
            VPD      = self.packets[i][3] | (VPD << 8)
        
        self.put(self.packets[0][0], self.packets[0][1], self.out_ann, [3, 
        ['SMBusAddr: %02X' % SMBusAddr, 
        '%02X' % SMBusAddr, 
        'SMBusAddr', 
        'CC']])
        self.put(self.packets[0][0], self.packets[256][1], self.out_ann, [12, ['VPD Read / EEPROMM', 'VPD Read', 'VPD']])
        
        Offset = 1
        # Common Header
        
        IPMIVER = self.packets[Offset][3]           # IPMI Format Version Number
        IUAOFF = self.packets[Offset + 1][3]        # Internal Use Area Starting Offset
        CIAOFF = self.packets[Offset + 2][3]        # Chassis Info Area Starting Offset
        BIAOFF = self.packets[Offset + 3][3]        # Board Info Area Starting Offset
        PIAOFF = self.packets[Offset + 4][3]        # Product Info Area Starting Offset
        MRIOFF = self.packets[Offset + 5][3]        # MultiRecord Info Area Starting Offset
        BFC = self.packets[Offset + 6][3]           # Boot Failure Code
        CHCHK = self.packets[Offset + 7][3]         # Common Header Checksum
        
        self.put(self.packets[Offset][0], self.packets[Offset + 7][1], self.out_ann, [6, ['VPD Common Header', 'Common Header', 'CH']])
        self.put(self.packets[Offset][0], self.packets[Offset + 7][1], self.out_ann, [3, 
        ['IPMIVER %02X | IUAOFF %02X | CIAOFF %02X | BIAOFF %02X | PIAOFF %02X | MRIOFF %02X | BFC %02X | CHCHK %02X' % (IPMIVER, IUAOFF, CIAOFF, BIAOFF, PIAOFF, MRIOFF, BFC, CHCHK), 
        'IPMIVER | IUAOFF | CIAOFF | BIAOFF | PIAOFF | MRIOFF | BFC | CHCHK', 
        '%02X | %02X | %02X | %02X | %02X | %02X | %02X | %02X' % (IPMIVER, IUAOFF, CIAOFF, BIAOFF, PIAOFF, MRIOFF, BFC, CHCHK),
        'CH']])
        
        DicVPDTable = {
            # Common Header
            0 : ['IPMI Format Version Number'],
            1 : ['Internal Use Area Starting Offset'],
            2 : ['Chassis Info Area Starting Offset'],
            3 : ['Board Info Area Starting Offset'],
            4 : ['Product Info Area Starting Offset'],
            5 : ['MultiRecord Info Area Starting Offset'],
            6 : ['Boot Failure Code'],
            7 : ['Common Header Checksum'],
            
            # Product Info Area
            8 : ['IPMI Format Version Number'],
            9 : ['Product Info Area Length'],
            10 : ['Language Code'],
            11 : ['Manufacturer Name Type/Length'],
            12 : ['Manufacturer Name'],
            13 : ['Product Name Type/Length'],
            14 : ['Product Name'],
            15 : ['Product Part/Model Number Type/Length'],
            16 : ['Product Part/Model Number'],
            17 : ['Product Version Type/Length'],
            18 : ['Product Version'],
            19 : ['Product Serial Number Type/Length'],
            20 : ['Product Serial Number'],
            21 : ['Asset Tag Type/Length'],
            22 : ['Asset Tag'],
            23 : ['FRU File ID Type/Length'],
            24 : ['FRU File ID'],
            25 : ['Custom Product Info Area'],
            26 : ['End of Record'],
            27 : ['ZerosPadding'],
            28 : ['Product Info Area'],
        }
        
        # Product Info Area
        if (PIAOFF * 8) != 0:
            IPMIVER = self.packets[Offset + 8][3]
            PALEN = self.packets[Offset + 9][3]
            LCODE = self.packets[Offset + 10][3]
            self.put(self.packets[Offset + 8][0], self.packets[Offset + 10][1], self.out_ann, [3, 
            ['IPMIVER %02X | PALEN %02X | LCODE %02X' % (IPMIVER, PALEN, LCODE), 
            'IPMIVER | MNAME | LCODE', 
            '%02X | %02X | %02X' % (IPMIVER, PALEN, LCODE),
            'PIA']])
            
            MNTL = self.packets[Offset + 11][3]
            Offset += 12
            Bytes = self.Type_Length_Byte(MNTL) + Offset
            MNAME = 0
            MNAME2 = ''
            for j in range(Offset, Bytes):
                MNAME = self.packets[j][3] | (MNAME << 8)
                MNAME2 = MNAME2 + "".join(chr(int(self.packets[j][3])))
            self.put(self.packets[Offset - 1][0], self.packets[Bytes - 1][1], self.out_ann, [3, 
            ['MNTL %02X | MNAME %X (%s)' % (MNTL, MNAME, MNAME2), 'MNTL %02X | MNAME %s' % (MNTL, MNAME2), 
            '%02X | %s' % (MNTL, MNAME2), 'MNTL | MNAME', 'MN']])
            Offset = Bytes
            
            
            PNTL = self.packets[Offset][3]
            Offset += 1
            Bytes = self.Type_Length_Byte(PNTL) + Offset
            PNAME = 0
            PNAME2 = ''
            for j in range(Offset, Bytes):
                PNAME = self.packets[j][3] |(PNAME << 8)
                PNAME2 = PNAME2 + "".join(chr(int(self.packets[j][3])))
            self.put(self.packets[Offset - 1][0], self.packets[Bytes - 1][1], self.out_ann, [3, 
            ['PNTL %02X | PNAME %X (%s)' % (PNTL, PNAME, PNAME2), 'PNTL %02X | PNAME %s' % (PNTL, PNAME2), 
            '%02X | %s' % (PNTL, PNAME2), 'PNTL | PNAME', 'PN']])
            Offset = Bytes
            
            
            PPMNNTL = self.packets[Offset][3]
            Offset += 1
            Bytes = self.Type_Length_Byte(PPMNNTL) + Offset
            PPMN = 0
            PPMN2 = ''
            for j in range(Offset, Bytes):
                PPMN = self.packets[j][3] |(PPMN << 8)
                PPMN2 = PPMN2 + "".join(chr(int(self.packets[j][3])))
            self.put(self.packets[Offset - 1][0], self.packets[Bytes - 1][1], self.out_ann, [3, 
            ['PPMNNTL %02X | PPMN %X (%s)' % (PPMNNTL, PPMN, PPMN2), 'PPMNNTL %02X | PPMN %s' % (PPMNNTL, PPMN2), 
            '%02X | %s' % (PPMNNTL, PPMN2), 'PPMNNTL | PPMN', 'PPMN']])
            Offset = Bytes


            PVTL = self.packets[Offset][3]
            Offset += 1
            Bytes = self.Type_Length_Byte(PVTL) + Offset
            PVER = 0
            PVER2 = ''
            for j in range(Offset, Bytes):
                PVER = self.packets[j][3] |(PVER << 8)
                PVER2 = PVER2 + "".join(chr(int(self.packets[j][3])))
            self.put(self.packets[Offset - 1][0], self.packets[Bytes - 1][1], self.out_ann, [3, 
            ['PVTL %02X | PVER %X (%s)' % (PVTL, PVER, PVER2), 'PVTL %02X | PVER %s' % (PVTL, PVER2), 
            '%02X | %s' % (PVTL, PVER2), 'PVTL | PVER', 'PV']])
            Offset = Bytes


            PSNTL = self.packets[Offset][3]
            Offset += 1
            Bytes = self.Type_Length_Byte(PSNTL) + Offset
            PSN = 0
            PSN2 = ''
            for j in range(Offset, Bytes):
                PSN = self.packets[j][3] |(PSN << 8)
                PSN2 = PSN2 + "".join(chr(int(self.packets[j][3])))
            self.put(self.packets[Offset - 1][0], self.packets[Bytes - 1][1], self.out_ann, [3, 
            ['PSNTL %02X | PSN %X (%s)' % (PSNTL, PSN, PSN2), 'PSNTL %02X | PSN %s' % (PSNTL, PSN2), 
            '%02X | %s' % (PSNTL, PSN2), 'PSNTL | PSN', 'PSN']])
            Offset = Bytes


            ATTL = self.packets[Offset][3]
            Offset += 1
            Bytes = self.Type_Length_Byte(ATTL) + Offset
            Bytes = Bytes + 1 if ATTL == 0 else Bytes
            AT = 0
            AT2 = ''
            for j in range(Offset, Bytes):
                AT = self.packets[j][3] |(AT << 8)
                AT2 = AT2 + "".join(chr(int(self.packets[j][3])))
            self.put(self.packets[Offset - 1][0], self.packets[Bytes - 1][1], self.out_ann, [3, 
            ['ATTL %02X | AT %X (%s)' % (ATTL, AT, AT2), 'ATTL %02X | AT %s' % (ATTL, AT2), 
            '%02X | %s' % (ATTL, AT2), 'ATTL | AT', 'AT']])
            Offset = Bytes
            
            
            FFITL = self.packets[Offset][3]
            Offset += 1
            Bytes = self.Type_Length_Byte(FFITL) + Offset
            Bytes = Bytes + 1 if FFITL == 0 else Bytes
            FFI = 0
            FFI2 = ''
            for j in range(Offset, Bytes):
                FFI = self.packets[j][3] |(FFI << 8)
                FFI2 = FFI2 + "".join(chr(int(self.packets[j][3])))
            self.put(self.packets[Offset - 1][0], self.packets[Bytes - 1][1], self.out_ann, [3, 
            ['FFITL %02X | FFI %X (%s)' % (FFITL, FFI, FFI2), 'FFITL %02X | FFI %s' % (FFITL, FFI2), 
            '%02X | %s' % (FFITL, FFI2), 'FFITL | FFI', 'FFI']])
            Offset = Bytes
            
            
            CPIA = self.packets[Offset][3]
            EOR = self.packets[Offset + 1][3]
            Offset += 2
            BytPadd = Offset % 8
            Pad = 0
            for j in range(Offset, (8 - BytPadd) + Offset): 
                Pad = self.packets[j][3] | (Pad << 8)
            Offset += (8 - BytPadd)
            PICHK = self.packets[Offset][3]
            self.put(self.packets[Bytes][0], self.packets[Offset][1], self.out_ann, [3, 
            ['CPIA %02X | EOR %02X | PICHK %02X' % (CPIA, EOR, PICHK), '%02X | %02X | %02X' % (CPIA, EOR, PICHK),
            'CPIA | EOR | PICHK', 'CH']])
            self.put(self.packets[(PIAOFF * 8) + 1][0], self.packets[Offset][1], self.out_ann, [6, ['VPD Product Info Area', 'Product Info Area', 'PIA']])


        
        # NVMe MultiRecord Area
        if (MRIOFF * 8) != 0:
            Offset = (MRIOFF * 8) + 1
            RTI     = self.packets[Offset][3]       # Record Type Identifier
            RFMT    = self.packets[Offset + 1][3]   # Record Format
            LREC    = bool((RFMT >> 7) & 0x1)       # Last Record
            RVER    = (RFMT & 0x7F)                 # Record Version
            RLEN    = self.packets[Offset + 2][3]   # Record Length
            RCSUM   = self.packets[Offset + 3][3]   # Record Checksum
            HSUM    = self.packets[Offset + 4][3]   # Header Checksum
            NMAVN   = self.packets[Offset + 5][3]   # NMVe Multirecord Area Version Number
            FF      = self.packets[Offset + 6][3]   # Format Factor
            I1P8PSR = self.packets[Offset + 13][3]  # Initial 1.8V Power Supply Requirements
            M1P8PSR = self.packets[Offset + 14][3]  # Maximum 1.8V Power Supply Requirements
            I3P3PSR = self.packets[Offset + 15][3]  # Initial 3.3V Power Supply Requirements
            M3P3PSR = self.packets[Offset + 16][3]  # Maximum 3.3V Power Supply Requirements
            M3P3APSR = self.packets[Offset + 18][3] # Maximum 3.3V Aux Power Supply Requirements
            I5PSR   = self.packets[Offset + 19][3]  # Initial 5V Power Supply Requirements
            M5PSR   = self.packets[Offset + 20][3]  # Maximum 5V Power Supply Requirements
            I12PSR  = self.packets[Offset + 21][3]  # Initial 12V Power Supply Requirements
            M12PSR  = self.packets[Offset + 22][3]  # Maximum 12V Power Supply Requirements
            MTL     = self.packets[Offset + 23][3]  # Maximum Thermal Load
            TNVMCAP = 0                             # Total NVM Capacity
            for j in range(Offset + 24, Offset + 37):
                TNVMCAP = self.packets[j][3]  | (TNVMCAP << 8)
            Factor,Description = UPD_FORM_FACTOR[FF]
            self.put(self.packets[Offset][0], self.packets[Offset + 63][1], self.out_ann, [6, ['VPD NVMe MultiRecord Area', 'NVMe MultiRecord Area', 'NMA']])
            
            self.put(self.packets[Offset][0], self.packets[Offset + 4][1], self.out_ann, [3, 
            ['Record Type Identifier %02X | Last Record %r | Record Version %02X | Record Length %02X | Record Checksum %02X | Header Checksum %02X' % (RTI, LREC, RVER, RLEN, RCSUM, HSUM), 
            'RTI %02X | LREC %r | RVER %02X | RLEN %02X | RCSUM %02X | HSUM %02X' % (RTI, LREC, RVER, RLEN, RCSUM, HSUM), 
            'RTI %02X | RFMT %02X | RLEN %02X | RCSUM %02X | HSUM %02X' % (RTI, RFMT, RLEN, RCSUM, HSUM), 
            '%02X | %02X | %02X | %02X | %02X' % (RTI, RFMT, RLEN, RCSUM, HSUM),
            'RTI | RFMT | RLEN | RCSUM | HSUM | CHCHK', 
            'NMA']])
            self.put(self.packets[Offset + 5][0], self.packets[Offset + 6][1], self.out_ann, [3, 
            ['NMVe Multirecord Area Version Number %02X | Format Factor ► Interface: %s ─ Description: %s' % (NMAVN, Factor, Description), 
            'NMAVN %02X | FF ► Intf: %s Desc: %s' % (NMAVN, Factor, Description), 
            'NMAVN %02X | FF %02X' % (NMAVN, FF), 
            '%02X | %02X' % (NMAVN, FF),
            'NMA']])
            self.put(self.packets[Offset + 7][0], self.packets[Offset + 12][1], self.out_ann, [3, 
            ['Reserved', 
            'RSVD', 
            '00']])
            self.put(self.packets[Offset + 13][0], self.packets[Offset + 14][1], self.out_ann, [3, 
            ['Initial 1.8V Power Supply Requirements %02X | Maximum 1.8V Power Supply Requirements %02X' % (I1P8PSR, M1P8PSR), 
            'I1P8PSR %02X | M1P8PSR %02X' % (I1P8PSR, M1P8PSR), 
            '1.8PSR']])
            self.put(self.packets[Offset + 15][0], self.packets[Offset + 18][1], self.out_ann, [3, 
            ['Initial 3.3V Power Supply Requirements %02X | Maximum 3.3V Power Supply Requirements %02X | Maximum 3.3V Aux Power Supply Requirements %02X' % (I3P3PSR, M3P3PSR, M3P3APSR), 
            'I3P3PSR %02X | M3P3PSR %02X | M3P3APSR %02X' % (I3P3PSR, M3P3PSR, M3P3APSR), 
            '3.3PSR']])
            self.put(self.packets[Offset + 19][0], self.packets[Offset + 20][1], self.out_ann, [3, 
            ['Initial 5V Power Supply Requirements %02X | Maximum 5V Power Supply Requirements %02X' % (I5PSR, M5PSR), 
            'I5PSR %02X | M5PSR %02X' % (I5PSR, M5PSR), 
            '5PSR']])
            self.put(self.packets[Offset + 21][0], self.packets[Offset + 22][1], self.out_ann, [3, 
            ['Initial 12V Power Supply Requirements %02X | Maximum 12V Power Supply Requirements %02X' % (I12PSR, M12PSR), 
            'I12PSR %02X | M12PSR %02X' % (I12PSR, M12PSR), 
            '12PSR']])
            self.put(self.packets[Offset + 23][0], self.packets[Offset + 36][1], self.out_ann, [3, 
            ['Maximum Thermal Load %02X | Total NVM Capacity %d' % (MTL, TNVMCAP), 
            'MTL %02X | TNVMCAP %X' % (MTL, TNVMCAP), 
            'CAP']])
            
            if RLEN == 0x3B:
                self.put(self.packets[Offset + 37][0], self.packets[Offset + 63][1], self.out_ann, [3, 
                ['Padding 00', 
                'Padding', 
                'PAD']])
                


        # NVMe PCIe Port MultiRecord Area
            Offset += 64
            RTI         = self.packets[Offset][3]       # Record Type Identifier
            RFMT        = self.packets[Offset + 1][3]   # Record Format
            LREC        = bool((RFMT >> 7) & 0x1)       # Last Record
            RVER        = (RFMT & 0x7F)                 # Record Version
            RLEN        = self.packets[Offset + 2][3]   # Record Length
            RCSUM       = self.packets[Offset + 3][3]   # Record Checksum
            HSUM        = self.packets[Offset + 4][3]   # Header Checksum
            NPCIEPMAVN  = self.packets[Offset + 5][3]   # NVMe PCIe Port MultiRecord Area Version Number
            PCIEPN      = self.packets[Offset + 6][3]   # PCIe Port Number
            PINFO       = self.packets[Offset + 7][3]   # Port Information
            PCIELS      = self.packets[Offset + 8][3]   # PCIe Link Speed
            PCIEMLW     = self.packets[Offset + 9][3]   # PCIe Maximum Link Width
            MCTPS       = self.packets[Offset + 10][3]  # MCTP Support
            RCCAP       = self.packets[Offset + 11][3]  # Ref Clk Capability
            PORTID      = self.packets[Offset + 12][3]  # Port Identifier
            
            PCIEMLWmap = PCIE_MAX_LINK_WIDTH.get(PCIEMLW, 'Reserved')
            
            self.put(self.packets[Offset][0], self.packets[Offset + 15][1], self.out_ann, [6, ['VPD NVMe PCIe Port MultiRecord Area', 'NVMe PCIe Port MultiRecord Area', 'NPMA']])
            
            self.put(self.packets[Offset][0], self.packets[Offset + 5][1], self.out_ann, [3, 
            ['Record Type Identifier %02X | Last Record %r | Record Version %02X | Record Length %02X | Record Checksum %02X | Header Checksum %02X | NVMe PCIe Port MultiRecord Area Version Number %02X' % (RTI, LREC, RVER, RLEN, RCSUM, HSUM, NPCIEPMAVN), 
            'RTI %02X | LREC %r | RVER %02X | RLEN %02X | RCSUM %02X | HSUM %02X | NPCIEPMAVN %02X' % (RTI, LREC, RVER, RLEN, RCSUM, HSUM, NPCIEPMAVN), 
            'RTI %02X | RFMT %02X | RLEN %02X | RCSUM %02X | HSUM %02X | NPCIEPMAVN %02X' % (RTI, RFMT, RLEN, RCSUM, HSUM, NPCIEPMAVN), 
            '%02X | %02X | %02X | %02X | %02X | %02X' % (RTI, RFMT, RLEN, RCSUM, HSUM, NPCIEPMAVN),
            'RTI | RFMT | RLEN | RCSUM | HSUM | CHCHK | NPCIEPMAVN', 
            'NPMA']])
            self.put(self.packets[Offset + 6][0], self.packets[Offset + 9][1], self.out_ann, [3, 
            ['PCIe Port Number %02X | Port Information %02X | PCIe Link Speed ► 2.5: %r ▬ 5: %r ▬ 8: %r ▬ 16: %r ▬ 32: %r ▬ 64: %r | PCIe Maximum Link Width: %s' % (PCIEPN, PINFO, bool(PCIELS & 1), bool(PCIELS & 2), bool(PCIELS & 4), bool(PCIELS & 8), bool(PCIELS & 16), bool(PCIELS & 32), PCIEMLWmap), 
            'PCIEPN %02X | PINFO %02X | PCIELS ► 2.5: %d ▬ 5: %d ▬ 8: %d ▬ 16: %d ▬ 32: %d ▬ 64: %d | PCIEMLW: %s' % (PCIEPN, PINFO, bool(PCIELS & 1), bool(PCIELS & 2), bool(PCIELS & 4), bool(PCIELS & 8), bool(PCIELS & 16), bool(PCIELS & 32), PCIEMLWmap), 
            'PCIEPN %02X | PINFO %02X | PCIELS %02X | PCIEMLW: %s' % (PCIEPN, PINFO, PCIELS, PCIEMLWmap), 
            'PCIEPN | PINFO | PCIELS | PCIEMLW', 
            'PCIe']])
            self.put(self.packets[Offset + 10][0], self.packets[Offset + 12][1], self.out_ann, [3, 
            ['MCTP Support %02X | Ref Clk Capability ► RefClk Support %r ▬ Separate RefClk with SSC Support %r ▬ Separate RefClk with No SSC Support %r ▬ Common RefClk Support %r | Port Identifier %02X' % (MCTPS, bool(RCCAP & 8), bool(RCCAP & 4), bool(RCCAP & 2), bool(RCCAP & 1), PORTID), 
            'MCTPS %02X | RCCAP ► RCS %r ▬ SRCSS %r ▬ SRCNSS %r ▬ CRCS %r | PORTID %02X' % (MCTPS, bool(RCCAP & 8), bool(RCCAP & 4), bool(RCCAP & 2), bool(RCCAP & 1), PORTID), 
            'MCTPS %02X | RCCAP %02X | PORTID %02X' % (MCTPS, RCCAP, PORTID), 
            'MCTPS | RCCAP | PORTID', 
            'NPMA']])

            if RLEN == 0x0B:
                self.put(self.packets[Offset + 13][0], self.packets[Offset + 15][1], self.out_ann, [3, 
                ['Padding 00', 
                'Padding', 
                'PAD']])

        # Topology MultiRecord Area
            Offset += 16
            RTI         = self.packets[Offset][3]       # Record Type Identifier
            RFMT        = self.packets[Offset + 1][3]   # Record Format
            LREC        = bool((RFMT >> 7) & 0x1)       # Last Record
            RVER        = (RFMT & 0x7F)                 # Record Version
            RLEN        = self.packets[Offset + 2][3]   # Record Length
            RCSUM       = self.packets[Offset + 3][3]   # Record Checksum
            HSUM        = self.packets[Offset + 4][3]   # Header Checksum
            VNUM        = self.packets[Offset + 5][3]   # Version Number
            ELEMC       = self.packets[Offset + 7][3]   # Element Count
            self.put(self.packets[Offset][0], self.packets[Offset + 7][1], self.out_ann, [6, ['VPD Topology MultiRecord Area', 'Topology MultiRecord Area', 'TMA']])
            
            self.put(self.packets[Offset][0], self.packets[Offset + 7][1], self.out_ann, [3, 
            ['Topology MultiRecord Area', 
            'TMA']])
            
            Offset += 8
            for j in range(0, ELEMC):
                TYP     = self.packets[Offset][3]       # Type
                TYPMap = ELEMENT_DESCRIPTOR_TYPE.get(TYP, 'Reserveed')
                REV     = self.packets[Offset + 1][3]   # Revision
                LEN     = self.packets[Offset + 2][3]   # Length
                TSINFO = 0
                self.put(self.packets[Offset][0], self.packets[Offset + LEN - 1][1], self.out_ann, [3, 
                ['Element Descriptor %d' % j, 
                'ED%d' % j]])
                self.put(self.packets[Offset][0], self.packets[Offset + LEN - 1][1], self.out_ann, [6, 
                ['TMA Element Descriptor %d' % j, 'TMA ED%d' % j, 'ED%d' % j]])
                for k in range(3, LEN):
                    TSINFO  = self.packets[Offset + k][3] | (TSINFO << 8)  # Type-Specific Information
                    
                    if TYP == 1:    # Extended Element Descriptor
                        EXTC = TSINFO
                        
                    elif TYP == 2:  # Upstream Connector Element Descriptor
                        FF      = self.packets[Offset + 3][3]   # Format Factor
                        LPTR    = self.packets[Offset + 4][3]   # Label Pointer
                        MAXAPWR = self.packets[Offset + 7][3]   # Maximum Auxiliary Power
                        MAXPWR  = self.packets[Offset + 9][3] | (self.packets[Offset + 8][3] << 8)   # Maximum Power
                        UPDC    = self.packets[Offset + 10][3]   # Upstream Port Descriptor Count
                        # Upstream Port Descriptor List
                        Factor,Description = UPD_FORM_FACTOR[FF]
                        UPDOffset = Offset + 11
                        for l in range(0, UPDC):
                            if self.packets[UPDOffset][3] == 0:
                                TYP2W = self.packets[UPDOffset][3]       # Type
                                LEN2W = self.packets[UPDOffset + 1][3]   # Length
                                CNT2W = self.packets[UPDOffset + 2][3]   # Count
                                for m in range(3,CNT2W + 3):
                                    TYP2W = self.packets[UPDOffset + m][3] | (TYP2W << 8)   # 2-Wire Pointer List
                                UPDOffset += LEN2W
                            elif self.packets[UPDOffset][3] == 1:
                                TYPPCIe = self.packets[UPDOffset][3]       # Type
                                LENPCIe = self.packets[UPDOffset + 1][3]   # Length
                                SL      = self.packets[UPDOffset + 2][3]   # Starting Lane
                                EL      = self.packets[UPDOffset + 3][3]   # Ending Lane
                                PCIEPTR = self.packets[UPDOffset + 4][3]   # PCIe Pointer
                                DPORT   = self.packets[UPDOffset + 5][3]   # Destination Port
                                UPDOffset += LENPCIe

                    elif TYP == 3:  # Expansion Connector Element 
                        EXTC = TSINFO
                    elif TYP == 4:  # Label Element Descriptor
                        EXTC = TSINFO
                    elif TYP == 5:  # 2-Wire Mux Element Descriptor
                        EXTC = TSINFO
                    elif TYP == 6:  # PCIe Switch Element Descriptor
                        EXTC = TSINFO
                    elif TYP == 7:  # NVM Subsystem Element Descriptor
                        EXTC = TSINFO
                    elif TYP == 8:  # FRU Information Device Element Descriptor
                        EXTC = TSINFO
                    elif TYP > 240: # Vendor specific
                        EXTC = TSINFO
                        
                Offset += LEN

    def handle_request_BMC(self):
        SMBusAddr = self.packets[0][3]
        CmdCode = self.packets[1][3]
        self.put(self.packets[0][0], self.packets[1][1], self.out_ann, [3, 
        ['SMBusAddr: %02X | Command Code: %02X' % (SMBusAddr, CmdCode), 
        '%02X | %02X' % (SMBusAddr, CmdCode), 
        'SMBusAddr|CmdCode', 
        'CC']])
        self.put(self.packets[0][0], self.packets[1][1], self.out_ann, [12, ['Command Code', 'CC', 'CC']])
        
    def handle_resp_bmc_cc_parser(self, data):
        cc_response = {
            # CC0
            0:["LOS",                               data[0],                                            "Length of Status"],
            1:["SFLGS",                             data[1],                                            "Status Flags"],
            2:["SARB",                              bool((data[1] >> 7) & 0x1),                         "SMBus Arbitration"],
            3:["DNR",                               bool((data[1] >> 6) & 0x1),                         "Drive Not Ready"],
            4:["DF",                                bool((data[1] >> 5) & 0x1),                         "Drive Functional"],
            5:["RNR",                               bool((data[1] >> 4) & 0x1),                         "Reset Not Required"],
            6:["P0PCIELA",                          bool((data[1] >> 3) & 0x1),                         "Port 0 PCIe Link Active"],
            7:["P1PCIELA",                          bool((data[1] >> 2) & 0x1),                         "Port 1 PCIe Link Active"],
            8:["NUSED",                             (data[1] & 0x3),                                    "Not Used"],
            9:["SMTW",                              data[2],                                            "SMART Warnings"],
            10:["CTEMP",                            data[3],                                            "Composite Temperature"],
            11:["PDLU",                             data[4],                                            "Percentage Drive Life Used"],
            12:["COTWT",                            data[5],                                            "Current Over Temp Warning Threshold"],
            13:["CPWR",                             data[6],                                            "Current Power"],
            14:["NVMSI",                            bool((data[6] >> 7) & 0x1),                         "NVM Subsystem Idle"],
            15:["NVMSP",                            (data[6] & 0x7F),                                   "NVM Subsystem Power"],
            16:["PEC0",                             data[7],                                            "Packet Error Code"],
            # CC8                                               
            17:["LENID",                            data[8],                                            "Length of Identification"],
            18:["VID",                              data[9] | (data[10] << 8),                          "Vendor Identifier"],
            19:["SN",                               0,                                                  "Serial Number"],
            20:["PEC8",                             data[31],                                           "Packet Error Code"],
            # CC32 Vendor Specific                      
            21:["VS",                               0,                                                  "Vendor Specific"],
        }

        #SNStr = SN.to_bytes((SN.bit_length() + 7) // 8, 'big').decode('ascii')
        for i in range(11, 30):
            cc_response[19][1] = data[i] | (cc_response[19][1] << 8)
        for i in range(32, 255):
            cc_response[21][1] = data[i] | (cc_response[21][1] << 8)
        
        return cc_response
        
    def handle_response_BMC_CC(self):
        CC_Ofst = 3
        SMBusAddr   = self.packets[0][3]
        CmdCode     = self.packets[1][3]
        SMBusAddrR  = self.packets[2][3]
        self.put(self.packets[0][0], self.packets[2][1], self.out_ann, [12, ['Command Code', 'CC', 'CC']])        
        self.put(self.packets[0][0], self.packets[2][1], self.out_ann, [3, 
        ['SMBusAddr: %02X | Command Code: %02X | SMBusAddrR: %02X' % (SMBusAddr, CmdCode, SMBusAddrR), 
        '%02X | %02X | %02X' % (SMBusAddr, CmdCode, SMBusAddrR), 
        'SMBusAddr | CmdCode | SMBusAddrR', 
        'CC']])
        
        Data = [self.packets[j][3] for j in range(12, len(self.packets))]
        cc_response = self.handle_resp_BMC_CC_parser(Data)

        CmdCode = 0x0
        # TBD, What happen if the CC in request is not 0, 8 or 32 / if the CC returns like ofset, change the matrix DicTblfields columns
        if CmdCode < 0x08: 
            EndByte = 10
            self.put(self.packets[3][0], self.packets[EndByte + 3][1], self.out_ann, [4, 
            ["%s: %02X | %s ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %d" %
            (cc_response[0][2], cc_response[0][1], cc_response[1][2], cc_response[1][1], cc_response[2][2], cc_response[2][1], cc_response[3][2], cc_response[3][1], cc_response[4][2], cc_response[4][1], cc_response[5][2], cc_response[5][1], cc_response[6][2], cc_response[6][1], cc_response[7][2], cc_response[7][1], cc_response[8][2], cc_response[8][1]),
            "%s: %02X | %s ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %d" %
            (cc_response[0][0], cc_response[0][1], cc_response[1][0], cc_response[1][1], cc_response[2][0], cc_response[2][1], cc_response[3][0], cc_response[3][1], cc_response[4][0], cc_response[4][1], cc_response[5][0], cc_response[5][1], cc_response[6][0], cc_response[6][1], cc_response[7][0], cc_response[7][1], cc_response[8][0], cc_response[8][1]),
            "%s | %s ► %s → %s → %s → %s → %s → %s → %s" % (cc_response[0][0], cc_response[1][0], cc_response[2][0], cc_response[3][0], cc_response[4][0], cc_response[5][0], cc_response[6][0], cc_response[7][0], cc_response[8][0])]])

            self.put(self.packets[3][0], self.packets[EndByte + 3][1], self.out_ann, [4, 
            ["%s: %02X | %s: %02X | %s: %02X | %s: %02X | %s ► %s: %r → %s: %02X | %s: %02X" %
            (cc_response[9][2], cc_response[9][1], cc_response[10][2], cc_response[10][1], cc_response[11][2], cc_response[11][1], cc_response[12][2], cc_response[12][1], cc_response[13][2], cc_response[13][1], cc_response[14][2], cc_response[14][1], cc_response[15][2], cc_response[15][1], cc_response[16][2], cc_response[16][1]),
            "%s: %02X | %s: %02X | %s: %02X | %s: %02X | %s ► %s: %r → %s: %02X | %s: %02X" %
            (cc_response[9][0], cc_response[9][1], cc_response[10][0], cc_response[10][1], cc_response[11][0], cc_response[11][1], cc_response[12][0], cc_response[12][1], cc_response[13][0], cc_response[13][1], cc_response[14][0], cc_response[14][1], cc_response[15][0], cc_response[15][1], cc_response[16][0], cc_response[16][1]),
            "%s | %s | %s | %s | %s ► %s → %s | %s" % (cc_response[9][0], cc_response[10][0], cc_response[11][0], cc_response[12][0], cc_response[13][0], cc_response[14][0], cc_response[15][0], cc_response[16][0])]])
        elif CmdCode < 0x20:
            EndByte = 24
            self.put(self.packets[3][0], self.packets[EndByte + 3][1], self.out_ann, [4, 
            ["%s: %02X | %s: %04X | %s: %X | %s: %02X" % (cc_response[17][2], cc_response[17][1], cc_response[18][2], cc_response[18][1], cc_response[19][2], cc_response[19][1], cc_response[20][2], cc_response[20][1]),
            "%s: %02X | %s: %04X | %s: %X | %s: %02X" % (cc_response[17][0], cc_response[17][1], cc_response[18][0], cc_response[18][1], cc_response[19][0], cc_response[19][1], cc_response[20][0], cc_response[20][1]),
            "%s | %s | %s | %s" % (cc_response[17][0], cc_response[18][0], cc_response[19][0], cc_response[20][0])]])
        elif CmdCode == 0xFF:
            EndByte = 32
            self.put(self.packets[3][0], self.packets[EndByte + 3][1], self.out_ann, [4, 
            ["%s: %02X | %s ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %d" %
            (cc_response[0][2], cc_response[0][1], cc_response[1][2], cc_response[1][1], cc_response[2][2], cc_response[2][1], cc_response[3][2], cc_response[3][1], cc_response[4][2], cc_response[4][1], cc_response[5][2], cc_response[5][1], cc_response[6][2], cc_response[6][1], cc_response[7][2], cc_response[7][1], cc_response[8][2], cc_response[8][1]),
            "%s: %02X | %s ► %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %r → %s: %d" %
            (cc_response[0][0], cc_response[0][1], cc_response[1][0], cc_response[1][1], cc_response[2][0], cc_response[2][1], cc_response[3][0], cc_response[3][1], cc_response[4][0], cc_response[4][1], cc_response[5][0], cc_response[5][1], cc_response[6][0], cc_response[6][1], cc_response[7][0], cc_response[7][1], cc_response[8][0], cc_response[8][1]),
            "%s | %s ► %s → %s → %s → %s → %s → %s → %s" % (cc_response[0][0], cc_response[1][0], cc_response[2][0], cc_response[3][0], cc_response[4][0], cc_response[5][0], cc_response[6][0], cc_response[7][0], cc_response[8][0])]])

            self.put(self.packets[3][0], self.packets[EndByte + 3][1], self.out_ann, [4, 
            ["%s: %02X | %s: %02X | %s: %02X | %s: %02X | %s ► %s: %r → %s: %02X | %s: %02X" %
            (cc_response[9][2], cc_response[9][1], cc_response[10][2], cc_response[10][1], cc_response[11][2], cc_response[11][1], cc_response[12][2], cc_response[12][1], cc_response[13][2], cc_response[13][1], cc_response[14][2], cc_response[14][1], cc_response[15][2], cc_response[15][1], cc_response[16][2], cc_response[16][1]),
            "%s: %02X | %s: %02X | %s: %02X | %s: %02X | %s ► %s: %r → %s: %02X | %s: %02X" %
            (cc_response[9][0], cc_response[9][1], cc_response[10][0], cc_response[10][1], cc_response[11][0], cc_response[11][1], cc_response[12][0], cc_response[12][1], cc_response[13][0], cc_response[13][1], cc_response[14][0], cc_response[14][1], cc_response[15][0], cc_response[15][1], cc_response[16][0], cc_response[16][1]),
            "%s | %s | %s | %s | %s ► %s → %s | %s" % (cc_response[9][0], cc_response[10][0], cc_response[11][0], cc_response[12][0], cc_response[13][0], cc_response[14][0], cc_response[15][0], cc_response[16][0])]])

            self.put(self.packets[3][0], self.packets[EndByte + 3][1], self.out_ann, [4, 
            ["%s: %02X | %s: %04X | %s: %X | %s: %02X" % (cc_response[17][2], cc_response[17][1], cc_response[18][2], cc_response[18][1], cc_response[19][2], cc_response[19][1], cc_response[20][2], cc_response[20][1]),
            "%s: %02X | %s: %04X | %s: %X | %s: %02X" % (cc_response[17][0], cc_response[17][1], cc_response[18][0], cc_response[18][1], cc_response[19][0], cc_response[19][1], cc_response[20][0], cc_response[20][1]),
            "%s | %s | %s | %s" % (cc_response[17][0], cc_response[18][0], cc_response[19][0], cc_response[20][0])]])

        elif CmdCode > 0x1F:
            EndByte = 223
            self.put(self.packets[3][0], self.packets[EndByte + 3][1], self.out_ann, [4, 
            ["%s: %X" % (cc_response[21][2], cc_response[21][1]),
            "%s: %X" % (cc_response[21][0], cc_response[21][1]),
            "%s" % cc_response[21][0]]])
            
        self.put(self.packets[3][0], self.packets[EndByte + 3][1], self.out_ann, [14, ['Command Code Data', 'Data', 'CCD']])        

    def handle_address_or_data(self, pins):
        scl, sda = pins
        self.pdu_bits += 1

        # Address and data are transmitted MSB-first.
        self.databyte <<= 1
        self.databyte |= sda
        self.bytesXbits.append(sda)

        # Remember the start of the first data/address bit.
        if self.bitcount == 0:
            self.ss_byte = self.samplenum

        # Store individual bits and their start/end samplenumbers.
        # In the list, index 0 represents the LSB (I²C transmits MSB-first).
        self.bits.insert(0, [sda, self.samplenum, self.samplenum])
        if self.bitcount > 0:
            self.bits[1][2] = self.samplenum
        if self.bitcount == 7:
            self.bitwidth = self.bits[1][2] - self.bits[2][2]
            self.bits[0][2] += self.bitwidth

        # Return if we haven't collected all 8 + 1 bits, yet.
        if self.bitcount < 7:
            self.bitcount += 1
            return

        d = self.databyte

        if self.state == 'FIND ADDRESS':
            self.put_address_word(self.databyte)
            self.wr = 0 if (self.databyte & 1) else 1
            if self.options['address_format'] == 'shifted':
                d = d >> 1

        bin_class = -1
        if self.state == 'FIND ADDRESS' and self.wr == 1:
            #cmd = 'ADDRESS WRITE'
            cmd = 'ADDRESS READ'
            bin_class = 0
        elif self.state == 'FIND ADDRESS' and self.wr == 0:
            cmd = 'ADDRESS READ'
            bin_class = 0
        elif self.state == 'FIND DATA' and self.wr == 1:
            #cmd = 'DATA WRITE'
            cmd = 'DATA READ'
            bin_class = 2
        elif self.state == 'FIND DATA' and self.wr == 0:
            cmd = 'DATA READ'
            bin_class = 2
        self.cmd = cmd
        self.ss, self.es = self.ss_byte, self.samplenum + self.bitwidth

        self.putb([bin_class, bytes([d])])

        for bit in self.bits:
            self.put(bit[1], bit[2], self.out_ann, [11, ['%d' % bit[0]]])

        if cmd.startswith('ADDRESS'):
            self.ss, self.es = self.samplenum, self.samplenum + self.bitwidth
            w = ['Write', 'Wr', 'W'] if self.wr else ['Read', 'Rd', 'R']
            self.putx([DicAnnotations[cmd][0], w])
            self.ss, self.es = self.ss_byte, self.samplenum

        # Save all Bytes in a Buffer
        self.packet_append()
        self.bytebuf.append(self.databyte)
        
        self.putx([DicAnnotations[cmd][0], ['%s: %02X' % (DicAnnotations[cmd][1], d), '%s: %02X' % (DicAnnotations[cmd][2], d), '%02X' % d]])
        self.bitcount = self.databyte = 0
        self.bits = []
        self.state = 'FIND ACK'

    def get_ack(self, pins):
        scl, sda = pins
        self.ss, self.es = self.samplenum, self.samplenum + self.bitwidth
        cmd = 'NACK' if (sda == 1) else 'ACK'
        self.error = 1 if (cmd == 'NACK') else 0
        self.putp([cmd, None])
        self.putx([DicAnnotations[cmd][0], DicAnnotations[cmd][1:]])
        # There could be multiple data bytes in a row, so either find
        # another data byte or a STOP condition next.
        self.state = 'FIND DATA'

    def handle_stop(self, pins):
        # Meta bitrate
        if self.samplerate:
            elapsed = 1 / float(self.samplerate) * (self.samplenum - self.pdu_start + 1)
            bitrate = int(1 / elapsed * self.pdu_bits)
            self.put(self.ss_byte, self.samplenum, self.out_bitrate, bitrate)
        cmd = 'STOP'
        self.ss, self.es = self.samplenum, self.samplenum
        self.putp([cmd, None])
        self.putx([DicAnnotations[cmd][0], DicAnnotations[cmd][1:]])
        self.put_payload_bytes()
        self.reset()
        self.state = 'FIND START'
        self.is_repeat_start = 0
        self.wr = -1
        self.bits = []

    def decode(self):
        while True:
            # State machine.
            if self.state == 'FIND START':
                # Wait for a START condition (S): SCL = high, SDA = falling.
                self.handle_start(self.wait({0: 'h', 1: 'f'}))
            elif self.state == 'FIND ADDRESS':
                # Wait for a data bit: SCL = rising.
                self.handle_address_or_data(self.wait({0: 'r'}))
            elif self.state == 'FIND DATA':
                # Wait for any of the following conditions (or combinations):
                #  0) Data sampling of receiver: SCL = rising, and/or
                #  1) START condition (S): SCL = high, SDA = falling, and/or
                #  2) STOP condition (P): SCL = high, SDA = rising
                pins = self.wait([{0: 'r'}, {0: 'h', 1: 'f'}, {0: 'h', 1: 'r'}])
                if self.matched[0]:
                    self.handle_address_or_data(pins)
                elif self.matched[1]:
                    self.handle_start(pins)
                elif self.matched[2]:
                    self.handle_stop(pins)
            elif self.state == 'FIND ACK':
                # Wait for a data/ack bit: SCL = rising.
                self.get_ack(self.wait({0: 'r'}))
