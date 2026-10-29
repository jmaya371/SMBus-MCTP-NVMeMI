import struct
# ============================================================
# Tables / Constants
# ============================================================
# ---- MCTP ----
MCTP_MSG_TYPES = {
    0x00: "MCTP Control",
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

MCTP_CTRL_MESSAGES = {
    0x01 : "Set Endpoint ID",
    0x02 : "Get Endpoint ID",
    0x03 : "Get Endpoint UUID",
    0x04 : "Get MCTP Version Support",
    0x05 : "Get Message Type Support",
    0x06 : "Get Vendor Defined Message Support",
    0x07 : "Resolve Endpoint ID",
    0x08 : "Allocate Endpoint IDs",
    0x09 : "Routing Information Update",
    0x0A : "Get Routing Table Entries",
    0x0B : "Prepare for Endpoint Discovery",
    0x0C : "Endpoint Discovery",
    0x0D : "Discovery Notify",
    0x0E : "Get Network ID",
    0x0F : "Query Hop",
    0x10 : "Resolve UUID",
    0x11 : "Query rate limit",
    0x12 : "Request TX rate limit",
    0x13 : "Update rate limit",
    0x14 : "Query Supported Interfaces",
    0xF0 : "Transport Specific",
    0xF1 : "Transport Specific",
    0xF2 : "Transport Specific",
    0xF3 : "Transport Specific",
    0xF4 : "Transport Specific",
    0xF5 : "Transport Specific",
    0xF6 : "Transport Specific",
    0xF7 : "Transport Specific",
    0xF8 : "Transport Specific",
    0xF9 : "Transport Specific",
    0xFA : "Transport Specific",
    0xFB : "Transport Specific",
    0xFC : "Transport Specific",
    0xFD : "Transport Specific",
    0xFE : "Transport Specific",
    0xFF : "Transport Specific"
}

MCTP_CTRL_COMPLETION_CODES = {
    0x00 : "SUCCESS",
    0x01 : "ERROR",
    0x02 : "ERROR_INVALID_DATA",
    0x03 : "ERROR_INVALID_LENGTH",
    0x04 : "ERROR_NOT_READY",
    0x05 : "ERROR_UNSUPPORTED_CMD",
    0x80 : "MESSAGE_TYPE_NUMBER_NOT_SUPPORTED", # Get MCTP Version Support completion code
    0x80 : "INSUFFICIENT_SPACE", #Insufficient space to add requested entries to internal routing table,  Routing Information Update completion code
    #0x80 - 0Xff : "COMMAND_SPECIFIC",
}

MCTP_CTRL_MESSAGE_TYPES = {
    0x00 : "MCTP Control (DSP0236)",
    0x01 : "PLDM (DSP0241)",
    0x02 : "NC-SI  (DSP0261)",
    0x03 : "Ethernet (DSP0261)",
    0x04 : "NVMe MI (DSP0235)",
    0x05 : "SPDM (DSP0275)",
    0x06 : "Secured Messages (DSP0276)",
    0x07 : "CXL FM API (DSP0234)",
    0x08 : "CXL CCI (DSP0271)",
    0x09 : "PCIe - MI (DSP0291)",
    0x7E : "Vendor Defined - PCI  (DSP0236)",
    0x7F : "Vendor Defined - IANA (DSP0236)",
    0xFF : "MCTP Base Specification (DSP0236)"
}

MCTP_CTRL_PHYSICAL_MEDIUM_IDENTIFIER = {
    0x00 : "Unspecified",
    0x01 : "SMBus 2.0 100 kHz",
    0x02 : "SMBus 2.0 or I2C 100 kHz",
    0x03 : "I2C 100 kHz (Standard-mode)",
    0x04 : "SMBus 3.0 or I2C 400 kHz (Fast-mode)",
    0x05 : "SMBus 3.0 or I2C 1 MHz (Fast-mode Plus)",
    0x06 : "I2C 3.4 MHz (High-speed mode)",
    0x07 : "Reserved",
    0x08 : "PCIe 1.1",
    0x09 : "PCIe 2.0",
    0x0A : "PCIe 2.1",
    0x0B : "PCIe 3.x",
    0x0C : "PCIe 4.x",
    0x0D : "PCIe 5.x or CXL 1.x / 2.x",
    0x0E : "PCIe 6.x Non-Flit Mode",
    0x0F : "PCI", # (PCI 1.0, 2.0, 2.1, 2.2, 2.3, 3.0, PCI-X 1.0, PCI-X 2.0)
    0x10 : "USB 1.1",
    0x11 : "USB 2.0",
    0x12 : "USB 3.0",
    # 0x13 : 0X17,"Reserved",
    0x14 : "Reserved",
    0x15 : "Reserved",
    0x16 : "Reserved",
    0x17 : "Reserved",
    0x18 : "NC-SI over RBT", # (A physical interface based on RMII as defined in DSP0222)",
    0x19 : "MCTP UCIe", # (DSP0290)
    0x1A : "MCTP PCC", # (DSP0292)
    # 0x1B : 0X1F, "Reserved",
    0x20 : "KCS Legacy", # (DSP0254 )Keyboard Controller Style (Fixed Address Decoding)",
    0x21 : "KCS over PCI", # (DSP0254)Keyboard Controller Style (Base Class 0xC0 Subclass 0x01)",
    0x22 : "Serial Host Legacy", # a register based UART interface(Fixed Address Decoding)",
    0x23 : "Serial Host over PCI", # a register based UART interface(Base Class 0x07 Subclass 0x00)",
    0x24 : "Asynchronous Serial", # an 8–bit asynchronous bi-directional(Between MCs and IMDs)",
    # 0x25 : 0x2F, "Reserved",
    0x30 : "I3C Basic",
    # 0x31 : 0x3F, "Reserved",
    0x40 : "PCIe 6.x Flit Mode or CXL 3.X",
    # 0x41 : 0xFF, "Reserved"
}

MCTP_CTRL_PHYSICAL_TRANSPORT_IDENTIFIER = {
    0x00 : "Reserved",
    0x01 : "MCTP over SMBus",       # (DSP0237)",
    0x02 : "MCTP over PCIe VDM",    # (DSP0238)",
    0x03 : "MCTP over USB",     # (DSP0283)",
    0x04 : "MCTP over KCS",     # (DSP0254)",
    0x05 : "MCTP over Serial",  # (DSP0253)",
    0x06 : "MCTP over I3C",     # (DSP0233)",
    0x07 : "MCTP over MMBI",    # (DSP0284)",
    0x08 : "MCTP over PCC",     # (DSP0292)",
    0x09 : "MCTP over UCIe",    # (DSP0290)",
    0xFF : "Vendor defined",
    # NOTE: A vendor-defined transport binding must meet the requirements in DSP0236 (in
    # particular, when being bridged to or from standard MCTP transport binding and media combinations).

    ## All other values are reserved
}

MCTP_CTRL_HOST_INTERFACE_IDENTIFIER = {
    0x01 : "Reserved",
    0x02 : "KCS", # Keyboard Controller Style – refer to the section titled “Keyboard Controller Style (KCS) Interface” of IPMI",
    0x03 : "8250 UART Register Compatible",
    0x04 : "16450 UART Register Compatible",
    0x05 : "16550/16550A UART Register Compatible",
    0x06 : "16650/16650A UART Register Compatible",
    0x07 : "16750/16750A UART Register Compatible",
    0x08 : "16850/16850A UART Register Compatible",
    0x09 : "I2C / SMBUS",
    0x0A : "I3C",
    0x0B : "PCIe VDM",
    0x0C : "MMBI",
    0x0D : "PCC",
    0x0E : "UCIe",
    0x0F : "USB",
    0x10 : "Reserved",
    # 0x10:0x3F Reserved
    # all other Assigned by the SMBIOS specification (DSP0134)
}

MCTP_CTRL_EID_OPERATION = {
    0x00 : "Set EID",
    0x01 : "Force EID",
    0x02 : "Reset EID",
    0x03 : "Set Discovered Flag"
}

MCTP_CTRL_EID_ASSIGNMENT_STATUS = {
    0x00 : "Accepted",
    0x01 : "Rejected",
}

MCTP_CTRL_EID_ALLOCATION_STATUS = {
    0x00 : "Don't use EID Pool",
    0x01 : "Required EID Pool Allocation",
    0x02 : "Already Allocated",
}

MCTP_CTRL_ENDPOINT_TYPE = {
    0x00 : "Simple Endpoint",
    0x01 : "Bus owner/Bridge",
}

MCTP_CTRL_ENDPOINT_ID_TYPE = {
    0x00 : "Dynamic EID",
    0x01 : "Static EID", # EID reflect the present setting
    0x02 : "Static EID", # Present EID is same as the static value
    0x03 : "Static EID", # Present EID is different than the static value
}

MCTP_CTRL_EID_ALLOCATION_OPERATION = {
    0x0 : "Allocate",
    0x1 : "Force Allocation",
    0x2 : "Get Allocation Information",
}

MCTP_CTRL_ALLOCATION_STATUS = {
    0x00 : "Accepted",
    0x01 : "Rejected",
}

MCTP_CTRL_ENTRY_TYPE = {
    0x00 : "Single Endpoint out Bridge",
    0x01 : "EID Range with EIDbridge",
    0x02 : "Single Endpoint in Bridge",
    0x03 : "EID Range without EID bridge",
}

MCTP_CTRL_DYNAMIC_STATIC_ENTRY = {
    0x00 : "Entry Dynamically created",
    0x01 : "Entry Statically created",
}


# ------------- Headers Messages
def handle_smbus_parser(data):
    smbus = {
        0 :     ['DSA',             data[0],                            "SMBus Destination Slave Address"],
        1 :     ['PTL',             data[1],                            "Command Code"],
        2 :     ['LEN',             data[2],                            "Byte Count"],
        3 :     ['SSA',             data[3],                            "SMBus Source Slave address"],
    }
    return smbus
    
def handle_mctp_parser(data):
    mctp = {
        0 :     ["HdrVer",          data[0],                            "MCTP version"],
        1 :     ["DstID",           data[1],                            "Destination endpoint ID"],
        2 :     ["SstID",           data[2],                            "Source endpoint ID"],
        3 :     ["Flg",             data[3],                            "flags"],
        4 :     ["SOM",             bool(data[3] & 0x80),               "   Start Of Message"],
        5 :     ["EOM",             bool(data[3] & 0x40),               "   End Of Message"],
        6 :     ["PSN",             (data[3] >> 4) & 0x3,               "   Packet sequence number"],
        7 :     ["TO",              bool(data[3] & 0x8),                "   Tag Owner"],
        8 :     ["MT",              (data[3] & 0x7),                    "   Message Tag"],
    }
    return mctp

def handle_mi_parser(data):
    nvme = {
        0 :     ["IC",              bool((data[0] >> 7) & 0x1),         "Integrity Check"],
        1 :     ["MT",              data[0] & 0x7F,                     "Message Type"],
        2 :     ["ROR",             bool((data[1]  >> 7) & 0x1),        "Request or Response"],
        3 :     ["NMIMT",           (data[1]  >> 3) & 0xF,              "NVMeMI Message type"],
        4 :     ["CSI",             bool(data[1] & 0x1),                "Command Slot"],
        5 :     ["CIAP",            bool((data[2]  >> 1) & 0x1),        "Command Initiated Auto Pause"],
        6 :     ["MEB",             bool(data[2] & 0x1),                "Management Endpoint Buffer"],
    }
    return nvme

def handle_mctp_control_parser(data):
    mctp_ctrl = {
        0 :     ["IC",              bool((data[0] >> 7) & 0x1),         "Integrity Check"],
        1 :     ["MT",              data[0] & 0x7F,                     "Message Type"],
        2 :     ["Rqbit",           bool((data[1] >> 7) & 0x1),         "Request bit"],
        3 :     ["Dbit",            bool((data[1] >> 6) & 0x1),         "Datagram bit"],
        5 :     ["IID",             data[1] & 0x1F,                     "Instance ID"],
        6 :     ["CmdCd",           data[2],                            "Command Code"],
    }
    return mctp_ctrl




def handle_set_endpoint_id_request(data):
    set_endpoint_id = {
        0 : ["OPE",     data[0] & 0x3,    "Operation"],
        1 : ["EID",     data[1],    "Endpoint ID"],
    }
    set_endpoint_id[0][1] = MCTP_CTRL_EID_OPERATION.get(set_endpoint_id[0][1], "Reserved")
    return set_endpoint_id

def handle_set_endpoint_id_response(data):
    set_endpoint_id_resp = {
        0 : ["CmpCode",             data[0],    "Completition Code"],
        1 : ["EIDAssSta",           (data[1] >> 4) & 0x3,   "EID assignment status"],
        2 : ["EIDAllSta",           (data[1] & 0x3),    "EID allocation status"],
        3 : ["EIDSett",             data[2],    "EID Setting"],
        4 : ["EIDPS",               data[3],    "EID Pool Size"],
    }
    set_endpoint_id_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(set_endpoint_id_resp[0][1], "Reserved")
    set_endpoint_id_resp[1][1] = MCTP_CTRL_EID_ASSIGNMENT_STATUS.get(set_endpoint_id_resp[1][1], "Reserved")
    set_endpoint_id_resp[2][1] = MCTP_CTRL_EID_ALLOCATION_STATUS.get(set_endpoint_id_resp[2][1], "Reserved")
    return set_endpoint_id_resp

def handle_get_endpoint_id_response(data):
    get_endpoint_id_resp = {
        0 : ["CmpCode",             data[0],                "Completition Code"],
        1 : ["EID",                 data[1],                "Endpoint ID"],
        2 : ["ETp",                 data[2],                "Endpoint Type"],
        3 : ["ETp",                 (data[2] >> 4) & 0x3,   "  Endpoint Type"],
        4 : ["EIDTp",               data[2] & 0x3,          "  Endpoint ID Type"],
        5 : ["OInf",                data[3],                "Other Information"],
    }
    get_endpoint_id_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(get_endpoint_id_resp[0][1], "Reserved")
    get_endpoint_id_resp[3][1] = MCTP_CTRL_ENDPOINT_TYPE.get(get_endpoint_id_resp[3][1], "Reserved")
    get_endpoint_id_resp[4][1] = MCTP_CTRL_ENDPOINT_ID_TYPE.get(get_endpoint_id_resp[4][1], "Reserved")
    return get_endpoint_id_resp

def handle_get_endpoint_uuid_response(data):
    get_endpoint_uuid_resp = {
        0 : ["CmpCode",             data[0],                "Completition Code"],
        1 : ["UUID",                data[1:16],             "Endpoint UUID"],
        2 : ["TL",                  data[1:4],              "time low"],
        3 : ["TM",                  data[5:6],              "time mid"],
        4 : ["TH",                  data[7:8],              "time high and version"],
        5 : ["CS",                  data[9:10],             "clock seq and reserved"],
        6 : ["Nd",                  data[11:16],            "node"],
    }
    get_endpoint_uuid_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(get_endpoint_uuid_resp[0][1], "Reserved")
    return get_endpoint_uuid_resp

def handle_get_mctp_version_request(data):
    get_mctp_version_req = {
        0 : ["MTN",                 data[0],                "Message Type Number"],
    }
    get_mctp_version_req[0][1] = MCTP_CTRL_MESSAGE_TYPES.get(get_mctp_version_req[0][1], "Reserved")

    return get_mctp_version_req

def handle_get_mctp_version_response(data):
    get_mctp_version_resp = {
        0 : ["CmpCode",             data[0],                "Completition Code"],
        1 : ["VNEC",                data[1],                "Version Number Entry Count"],
    }

    for i in range(0, get_mctp_version_resp[1][1] + 1):
        get_mctp_version_resp[2 + (i * 5)] = ["TL%d" % (i + 1),   data[(2 + (i * 4)) : (5 + (i * 4))], "Version Number entry %d" % (i + 1)]
        get_mctp_version_resp[3 + (i * 5)] = ["A",   data[(2 + (i * 4))], "Aplha"]
        get_mctp_version_resp[4 + (i * 5)] = ["UVN",   data[(3 + (i * 4))], "Update Version Number"]
        get_mctp_version_resp[5 + (i * 5)] = ["MnVN",   data[(4 + (i * 4))], "Minor Version Number"]
        get_mctp_version_resp[6 + (i * 5)] = ["MjVN",   data[(5 + (i * 4))], "Major Version Number"]
    get_mctp_version_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(get_mctp_version_resp[0][1], "Reserved")
    return get_mctp_version_resp

def handle_get_message_type_support_response(data):
    get_message_type_support_resp = {
        0 : ["CmpCode",             data[0],                "Completition Code"],
        1 : ["MMTC",                 data[1],                "MCTP Message Type Count"],
    }

    for i in range(0, get_message_type_support_resp[1][1] + 1):
        get_message_type_support_resp[2 + i] = ["MMT%d" % (i + 1),   data[2 + i], "MCTP Message Type %d" % (i + 1)]
        get_message_type_support_resp[2 + i][1] = MCTP_CTRL_MESSAGE_TYPES.get(get_message_type_support_resp[2 + i][1], "Reserved")
    get_message_type_support_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(get_message_type_support_resp[0][1], "Reserved")
    return get_message_type_support_resp

def handle_get_vendor_defined_message_support_request(data):
    get_vendor_defined_message_support_req = {
        0 : ["VIDSS",     data[0],                "Vendor ID Set Selector"],
    }
    return get_vendor_defined_message_support_req

def handle_get_vendor_defined_message_support_response(data):
    get_vendor_defined_message_support_resp = {
        0 : ["CmpCode",     data[0],                "Completition Code"],
        1 : ["VIDSSel",      data[1],                "Vendor ID Set Selector"],
    }
    get_vendor_defined_message_support_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(get_vendor_defined_message_support_resp[0][1], "Reserved")
    if get_vendor_defined_message_support_resp[1][1] < 0xFF:
        get_vendor_defined_message_support_resp[2] = ["VIDF",   data[2], "Vendor ID Format"]
        if get_vendor_defined_message_support_resp[2][1] == 0:
            get_vendor_defined_message_support_resp[3] = ["VIDD",   data[3:4], "Vendor ID Data"]
            get_vendor_defined_message_support_resp[4] = ["VID",   data[5:6], "Vendor ID"]
        elif get_vendor_defined_message_support_resp[2][1] == 1:
            get_vendor_defined_message_support_resp[3] = ["VIDD",   data[3:6], "Vendor ID Data"]
            get_vendor_defined_message_support_resp[4] = ["VID",   data[7:8], "Vendor ID"]
    return get_vendor_defined_message_support_resp

def handle_resolve_endpoint_id_request(data):
    resolve_endpoint_id_req = {
        0 : ["TEID",     data[0],                "Target Endpoint ID"],
    }
    return resolve_endpoint_id_req

def handle_resolve_endpoint_id_response(data):
    resolve_endpoint_id_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["BEID",     data[1],                "Bridge Endpoint ID"],
        2 : ["PA",     data[2:-1],                "Physical Address"]
    }
    resolve_endpoint_id_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(resolve_endpoint_id_resp[0][1], "Reserved")
    return resolve_endpoint_id_resp

def handle_allocate_endpoint_ids_request(data):
    allocate_endpoint_ids_req = {
        0 : ["OPE",     data[0] & 0x3,    "Operation"],
        1 : ["NEID",     data[1],    "Number of Endpoint IDs"],
        2 : ["SEID",     data[2],    "Starting Endpoint ID"],
    }

    allocate_endpoint_ids_req[0][1] = MCTP_CTRL_EID_ALLOCATION_OPERATION.get(allocate_endpoint_ids_req[0][1], "Reserved")
    return allocate_endpoint_ids_req

def handle_allocate_endpoint_ids_response(data):
    allocate_endpoint_ids_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["AS",     data[1] & 0x3,                "Allocation status"],
        2 : ["EIDPS",     data[2],                "Endpoint ID Pool Size"],
        3 : ["FEID",     data[3],                "First Endpoint ID"],
    }
    allocate_endpoint_ids_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(allocate_endpoint_ids_resp[0][1], "Reserved")
    allocate_endpoint_ids_resp[1][1] = MCTP_CTRL_ALLOCATION_STATUS.get(allocate_endpoint_ids_resp[1][1], "Reserved")
    return allocate_endpoint_ids_resp

def handle_routing_information_update_request(data):
    routing_information_update_req = {
        0 : ["NUE",     data[0],                "Count of update entries"],
        1 : ["UED",       data[1:-1],                "Update Entries Data"],
    }
    return routing_information_update_req

def handle_routing_information_update_response(data):
    routing_information_update_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
    }
    routing_information_update_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(routing_information_update_resp[0][1], "Reserved")
    return routing_information_update_resp

def handle_get_routing_table_entries_request(data):
    get_routing_table_entries_req = {
        0 : ["EH",     data[0],                "Entry Handle"],
    }
    return get_routing_table_entries_req

def handle_get_routing_table_entries_response(data):
    get_routing_table_entries_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["NEH",        data[1],                "Next Entry Handle"],
        2 : ["NRE",        data[2],                "Number of routing table entries"],
    }
    get_routing_table_entries_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(get_routing_table_entries_resp[0][1], "Reserved")
    for i in range(0, get_routing_table_entries_resp[2][1]):
        get_routing_table_entries_resp[3 + (i * 10)] = ["SEIDR", data[3 + (i * 10)], "Size of EID range"]
        get_routing_table_entries_resp[4 + (i * 10)] = ["SEID", data[4 + (i * 10)], "Starting EID"]
        get_routing_table_entries_resp[5 + (i * 10)] = ["ET", (data[5 + (i * 10)] >> 6) & 0x3, "  Entry Type"]
        get_routing_table_entries_resp[6 + (i * 10)] = ["D/SE", (data[5 + (i * 10)] >> 5) & 0x1, "  Dynamic/Static Entry"]
        get_routing_table_entries_resp[7 + (i * 10)] = ["PN", (data[5 + (i * 10)] & 0xF), "  Port number"]
        get_routing_table_entries_resp[8 + (i * 10)] = ["PTBI", data[6 + (i * 10)], "Physical Transport Binding Identifier"]
        get_routing_table_entries_resp[9 + (i * 10)] = ["PMTI", data[7 + (i * 10)], "Physical Media Type Identifier"]
        get_routing_table_entries_resp[10 + (i * 10)] = ["PAS", data[8 + (i * 10)], "Physical Address Size"]
        get_routing_table_entries_resp[11 + (i * 10)] = ["PA", data[9 + (i * 10):9 + (i * 10) + get_routing_table_entries_resp[10 + (i * 10)][1]], "Physical Address"]
        get_routing_table_entries_resp[12 + (i * 10)] = ["RTE%d" % i, data[3 + (i * 10):9 + (i * 10) + get_routing_table_entries_resp[10 + (i * 10)][1]], "Routing Table Entry %d" % i]
        get_routing_table_entries_resp[5 + (i * 10)][1] = MCTP_CTRL_ENTRY_TYPE.get(get_routing_table_entries_resp[5 + (i * 10)][1])
        get_routing_table_entries_resp[6 + (i * 10)][1] = MCTP_CTRL_DYNAMIC_STATIC_ENTRY.get(get_routing_table_entries_resp[6 + (i * 10)][1])
        get_routing_table_entries_resp[8 + (i * 10)][1] = MCTP_CTRL_PHYSICAL_TRANSPORT_IDENTIFIER.get(get_routing_table_entries_resp[8 + (i * 10)][1])
        get_routing_table_entries_resp[9 + (i * 10)][1] = MCTP_CTRL_PHYSICAL_MEDIUM_IDENTIFIER.get(get_routing_table_entries_resp[9 + (i * 10)][1])
    return get_routing_table_entries_resp

def handle_prepare_for_endpoint_discovery_response(data):
    prepare_for_endpoint_discovery_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
    }
    prepare_for_endpoint_discovery_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(prepare_for_endpoint_discovery_resp[0][1], "Reserved")
    return prepare_for_endpoint_discovery_resp
    
def handle_endpoint_discovery_response(data):
    endpoint_discovery_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
    }
    endpoint_discovery_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(endpoint_discovery_resp[0][1], "Reserved")
    return endpoint_discovery_resp
    
def handle_discovery_notify_response(data):
    discovery_notify_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
    }
    discovery_notify_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(discovery_notify_resp[0][1], "Reserved")
    return discovery_notify_resp
    
def handle_get_network_id_response(data):
    get_network_id_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["NID",        data[1:16],                "Network ID"],
        2 : ["TL",                  data[1:4],              "time low"],
        3 : ["TM",                  data[5:6],              "time mid"],
        4 : ["TH",                  data[7:8],              "time high and version"],
        5 : ["CS",                  data[9:10],             "clock seq and reserved"],
        6 : ["Nd",                  data[11:16],            "node"],
    }
    get_network_id_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(get_network_id_resp[0][1], "Reserved")
    return get_network_id_resp
    
def handle_query_hop_request(data):
    query_hop_req = {
        0 : ["TEID", data[0], "Target Endpoint ID"],
        1 : ["MT", data[1], "Message Type"]
    }
    return query_hop_req
    
def handle_query_hop_response(data):
    query_hop_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["EIDN", data[1], "EID next bridge"],
        2 : ["MT", data[2], "Message Type"],
        3 : ["MITUS", data[3:4], "Maximum supported Incoming Transmision Size"],
        4 : ["MOTUS", data[5:6], "Maximum supported Outcoming Transmision Size"] 
    }
    query_hop_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(query_hop_resp[0][1], "Reserved")
    return query_hop_resp
    
def handle_resolve_uuid_request(data):
    resolve_uuid_req = {
        0 : ["RUUID", data[0:15], "Requested UUID"],
        1 : ["EH", data[16], "Entry Handle"]
    }
    return resolve_uuid_req
    
def handle_resolve_uuid_response(data):
    resolve_uuid_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["NEH", data[1], "Next Entry Handle"],
        2 : ["NEID",     data[2],    "Number of Endpoint IDs"],
    }
    resolve_uuid_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(resolve_uuid_resp[0][1], "Reserved")
    for i in range(0, resolve_uuid_resp[2][1]):
        resolve_uuid_resp[4 + (i * 6)] = ["EID%d" % i, data[4 + (i * 6)], "Endpoint ID %d" % i]
        resolve_uuid_resp[5 + (i * 6)] = ["PTBTI%d" % i, data[5 + (i * 6)], "Physical Transport Binding Type Identifier %d" % i]
        resolve_uuid_resp[6 + (i * 6)] = ["PMTI%d" % i, data[6 + (i * 6)], "Physical Media Type Identifier %d" % i]
        resolve_uuid_resp[7 + (i * 6)] = ["PAS%d" % i, data[7 + (i * 6)], "Physical Address Size %d" % i]
        resolve_uuid_resp[8 + (i * 6)] = ["PA%d" % i, data[8 + (i * 6):8 + (i * 6) + resolve_uuid_resp[7 + (i * 6)][1]], "Physical Address %d" % i]
        resolve_uuid_resp[3 + (i * 6)] = ["RTE%d" % i, data[3 + (i * 6):8 + (i * 6) + resolve_uuid_resp[7 + (i * 6)][1]], "Routing table entry %d" % i]
        resolve_uuid_resp[5 + (i * 6)][1] = MCTP_CTRL_PHYSICAL_TRANSPORT_IDENTIFIER.get(resolve_uuid_resp[5 + (i * 6)][1])
        resolve_uuid_resp[6 + (i * 6)][1] = MCTP_CTRL_PHYSICAL_MEDIUM_IDENTIFIER.get(resolve_uuid_resp[6 + (i * 6)][1])
    return resolve_uuid_resp
    
def handle_query_rate_limit_response(data):
    query_rate_limit_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["RxBS",  data[1:4],                "RX: burst size"],
        2 : ["RxMRL",  data[5:8],                "RX: maximum rate limit,"],
        3 : ["TxMRL",  data[9:12],                "TX: Maximum rate limit"],
        4 : ["TxMinRL",  data[13:16],                "TX: Minimum rate limit"],
        5 : ["TxBS",  data[17:19],                "TX: burst size"],
        6 : ["TxPRLBS",  data[20:22],                "TX Present Rate Limit Burst"],
        7 : ["TxEIDMRL",  data[23:26],                "Tx EID Maximal rate limit"],
        8 : ["TxRLC",  data[27],                "TX Rate limiter capabilities"],
        9 : ["TxRLO",  bool(data[27] & 0x02),                "  TX Rate limiting operation  "],
        10 : ["TxRLSEID",  bool(data[27] & 0x01),                "  TX Rate limiting Support on EID"]
    }
    query_rate_limit_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(query_rate_limit_resp[0][1], "Reserved")
    return query_rate_limit_resp
    
def handle_request_tx_rate_limit_request(data):
    request_tx_rate_limit_req = {
        0 : ["TxBS",     data[0:3],                "Tx: EID maximal burst size"],
        1 : ["TxMRL",  data[4:6],                "TX: Maximum rate limit"]

    }
    return request_tx_rate_limit_req
    
def handle_request_tx_rate_limit_response(data):
    request_tx_rate_limit_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["TxBS",  data[1:4],                "TX: EID burst size"],
        2 : ["TxEIDMRL",  data[5:8],                "TX: EID rate limit,"],
    }
    request_tx_rate_limit_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(request_tx_rate_limit_resp[0][1], "Reserved")
    return request_tx_rate_limit_resp
    
def handle_update_rate_limit_request(data):
    update_rate_limit_req = {
        0 : ["TxBS",  data[0:2],                "TX: EID burst size"],
        1 : ["TxEIDMRL",  data[3:6],                "TX: EID rate limit,"],
    }
    return update_rate_limit_req
    
def handle_update_rate_limit_response(data):
    update_rate_limit_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
    }
    update_rate_limit_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(update_rate_limit_resp[0][1], "Reserved")
    return update_rate_limit_resp
    
def handle_query_supported_interfaces_response(data):
    query_supported_interfaces_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
        1 : ["SIC",     data[1],                "Supported Interfaces Count"]
    }
    query_supported_interfaces_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(query_supported_interfaces_resp[0][1], "Reserved")
    for i in range(query_supported_interfaces_resp[1][1]):
        query_supported_interfaces_resp[2 + (i * 2)] = ["IT%d" % i,     data[2 + (i * 2)],                "Interface Type %d" % i]
        query_supported_interfaces_resp[3 + (i * 2)] = ["IEID%d" % i,     data[3 + (i * 2)],                "Interface EID %d" % i]
        query_supported_interfaces_resp[2 + (i * 2)][1] = MCTP_CTRL_PHYSICAL_MEDIUM_IDENTIFIER.get(query_supported_interfaces_resp[2 + (i * 2)][1])

    return query_supported_interfaces_resp
    
def handle_transport_specific_request(data):
    transport_specific_req = {
        0 : ["PTBI",     data[0],                "MCTP Physical Transport Binding Identifier"],
        1 : ["PBI",     data[1],                "MCTP Physical Media Identifier"],
        2 : ["TSCD",     data[2:-1],                "Transport specific command data"]
    }
    transport_specific_req[0][1] = MCTP_CTRL_PHYSICAL_TRANSPORT_IDENTIFIER.get(transport_specific_req[0][1])
    transport_specific_req[1][1] = MCTP_CTRL_PHYSICAL_MEDIUM_IDENTIFIER.get(transport_specific_req[1][1])
    return transport_specific_req
    
def handle_transport_specific_response(data):
    transport_specific_resp = {
        0 : ["CmpCode",     data[0],                "Completion Code"],
    }
    transport_specific_resp[0][1] = MCTP_CTRL_COMPLETION_CODES.get(transport_specific_resp[0][1], "Reserved")
    return transport_specific_resp








def handle_generic_error_response(data):
    genErrResp = {
        0 :     ["STA",             data[0],                            "Status"],
    }
    ErrSpcFld = data[1] | (data[2] << 8) | (data[3] << 16)
    
    if genErrResp[0][1] == 4:
        genErrResp[1] = ["PEL",     ErrSpcFld,                          "Parameter Error Location"],
        genErrResp[2] = ["BYTLOC",  ErrSpcFld & 0x7,                    "   Byte Location"],
        genErrResp[3] = ["BITLOC",  (ErrSpcFld >> 8) & 0xFFFF,          "   Bit Location"],
    elif genErrResp[0][1] == 1:
        # divide by 10 to get the time in seconds or keep units (each unit equal to 100ms) 
        genErrResp[1] = ["MPRT",    (ErrSpcFld >> 8) & 0xFFFF,          "More Processing Required Time"],
        
    return genErrResp

def handle_Message_Integrity_Check(data):
    MIC = {
        0 : ["MIC",     data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24),                "Messages Integrity Check"],
    }
    
    return MIC

def handle_PEC(data):
    PEC = {
        0 : ["PEC",     data,                "Packet Error Checking"],
    }
    
    return PEC

# ------------- Request Messages
def handle_req_ctrl_prim_parser(data):
    CtrlPrimReq = {
        0 :     ["OPC",                                 data[0],                                    "Opcode"],
        1 :     ["TAG",                                 data[1],                                    "Tag"],
    }
    
    if CtrlPrimReq[0][1] == 0x03:# "Get State"
        CtrlPrimReq[2] = ["CESF",                       bool(data[2] & 0x1),                        "Clear Error State Flags"]
    elif CtrlPrimReq[0][1] == 0x04:# "Replay"
        CtrlPrimReq[2] = ["RRO",                        data[2],                                    "Response Replay Offset"]
    
    return CtrlPrimReq

def handle_req_nvme_mi_parser(data):
    nvme_mi_req = {
        0 :     ["OPC",                                 data[0],                                    "Opcode"],
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
        nvme_mi_req[1] = ["DW0",                    data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24),     "DWORD 0"]
        # DWORD 1 (Bytes: 20 - 23)
        nvme_mi_req[2] = ["DW1",                    data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24),  "DWORD 1"]
    return nvme_mi_req
    
def handle_req_nvme_admin_parser(data, Offset, Len, LastOpcode, SOM):
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

    if (admin_req[0][1] == 0x00 and LastOpcode == 0x02) or (admin_req[0][1] == 0x02):      # "Get Log Page",
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
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x06) or (admin_req[0][1] == 0x06):    # "Identify",
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
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x09) or (admin_req[0][1] == 0x09):    # "Set Features",
        # SQE DW 10
        admin_req[13] =  ["FID",                     DW10 & 0xFF,                                                                "Feature Identifier"]            
        admin_req[14] =  ["SV",                      bool((DW10 >> 31) & 0x01),                                                  "Save"]            
        # SQE DW 11
        # SQE DW 12
        # SQE DW 13
        # SQE DW 14
        admin_req[15] =  ["UIDX",                    DW14 & 0x7F,                                                                "UUID Index"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x0A) or (admin_req[0][1] == 0x0A):    # "Get Features",
        # SQE DW 10
        admin_req[13] =  ["FID",                     DW10 & 0xFF,                                                                "Feature Identifier"]            
        admin_req[14] =  ["SEL",                     ((DW10 >> 8) & 0x07),                                                         "Select"]            
        # SQE DW 11
        # SQE DW 12
        # SQE DW 13
        # SQE DW 14
        admin_req[15] =  ["UIDX",                    DW14 & 0x7F,                                                                "UUID Index"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x0D) or (admin_req[0][1] == 0x0D):    # "Namespace Management",
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
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x10) or (admin_req[0][1] == 0x10):    # "Firmware Commit",
        # SQE DW 10
        admin_req[13] =  ["FS",                     (DW10 & 0x07),                                                               "Firmware Slot"]            
        admin_req[14] =  ["CA",                      (DW10 >> 3) & 0x07,                                                        "Commit Action"]            
        admin_req[15] =  ["BPID",                    bool((DW10 >> 31) & 0x01),                                                   "Boot Partition ID"]            
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x11) or (admin_req[0][1] == 0x11):    # "Firmware Image Download",
        # SQE DW 10
        admin_req[13] = ["NUMD",                     DW10,                                                                       "Number of Dwords"]
        # SQE DW 11
        admin_req[14] = ["OFST",                     DW11,                                                                       "Offset"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x14) or (admin_req[0][1] == 0x14):    # "Device Self-Test",
        # SQE DW 10
        admin_req[13] = ["STC",                     (DW10 & 0x0F),                                                                       "Self-test Code"]
        # SQE DW 11
        # SQE DW 12
        # SQE DW 13
        # SQE DW 14
        # SQE DW 15
        admin_req[14] = ["DSTP",                     DW10,                                                                       "Device Self-test Parameter"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x15) or (admin_req[0][1] == 0x15):    # "Namespace attachment",
        # SQE DW 10
        admin_req[1] = ["SEL",                     (DW10 & 0xF),                                                                       "Select"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x1C) or (admin_req[0][1] == 0x1C):    # "Virtualization Management",
        # SQE DW 10
        admin_req[13] = ["ACT",                     (DW10 & 0xF),                                                                       "Action"]
        admin_req[14] = ["RT",                     (DW10 >> 8) & 0x7,                                                                       "Resource Type"]
        admin_req[15] = ["CNTLID",                     (DW10 >> 16) & 0xFFFF,                                                                       "Controller Identifier"]
        # SQE DW 11
        admin_req[16] = ["NR",                     (DW11 & 0xFFFF),                                                                       "Number of Controller Resources"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x20) or (admin_req[0][1] == 0x20):    # "Capacity Management",
        # SQE DW 10
        admin_req[13] = ["OPER",                     (DW10 & 0xF),                                                                       "Operation"]
        admin_req[14] = ["ELID",                     (DW10 >> 16) & 0xFFFF,                                                                       "Element Identifier"]
        # SQE DW 11
        admin_req[15] = ["CAPL",                     DW11,                                                                       "Capacity Lower"]
        # SQE DW 12
        admin_req[16] = ["CAPU",                     DW12,                                                                       "Capacity Upper"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x24) or (admin_req[0][1] == 0x24):    # "Lockdown",
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
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x28) or (admin_req[0][1] == 0x28):    # "Clear Exported NVM Resource Configuration",TBD
        # SQE DW 10
        # SQE DW 11
        # SQE DW 12
        # SQE DW 13
        # SQE DW 14
        # SQE DW 15
        admin_req[13] = ["DW10",                     DW10,                                                                       "DOWRD 10"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x2A) or (admin_req[0][1] == 0x2A):    # "Create Exported NVM Subsystem",
        # SQE DW 10
        admin_req[13] = ["RA",                     bool(DW10 & 0x100),                                                                       "Restricted Access"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x2D) or (admin_req[0][1] == 0x2D):    # "Manage Exported NVM Subsystem",
        # SQE DW 10
        admin_req[13] = ["SEL",                     (DW10 & 0xFF),                                                                       "Select"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x31) or (admin_req[0][1] == 0x31):    # "Manage Exported Namespace",
        # SQE DW 10
        admin_req[13] = ["SEL",                     (DW10 & 0xFF),                                                                       "Select"]
        admin_req[14] = ["MOS",                     (DW10 >> 8) & 0xFF,                                                                       "Management Operation Specific"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x35) or (admin_req[0][1] == 0x35):    # "Manage Exported Port",
        # SQE DW 10
        admin_req[13] = ["SEL",                     (DW10 & 0xFF),                                                                       "Select"]
        admin_req[14] = ["MOS",                     (DW10 >> 8) & 0xFF,                                                                       "Management Operation Specific"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x80) or (admin_req[0][1] == 0x80):    # "Format NVM",
        # SQE DW 10
        admin_req[13] = ["LBAFU",                (DW10 & 0xF),                                                                       "LBA Format Lower"]
        admin_req[14] = ["SES",                  (DW10 & 0x10),                                                                       "Metadata Settings"]
        admin_req[15] = ["PIL",                  (DW10 >> 5) & 0x7,                                                                       "Protection Information"]
        admin_req[16] = ["PI",                   (DW10 & 0x100),                                                                       "Protection Information Location"]
        admin_req[17] = ["MSET",                 (DW10 >> 5) & 0x7,                                                                       "Secure Erase Settings"]
        admin_req[18] = ["LBAFL",                (DW10 >> 12) & 0x3,                                                                       "LBA Format Upper"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x81) or (admin_req[0][1] == 0x81):    # "Security Send",
        # SQE DW 10
        admin_req[13] = ["NSFF",                     (DW10 >> 24) & 0xFF,                                                                       "NVMe Security Specific Field"]
        admin_req[14] = ["SPSP0",                     (DW10 >> 16) & 0xFF,                                                                       "SP Specific 0"]
        admin_req[15] = ["SPSP1",                     (DW10 >> 8) & 0xFF,                                                                       "SP Specific 1"]
        admin_req[16] = ["SECP",                     DW10 & 0xFF,                                                                       "Security Protocol"]
        # SQE DW 11
        admin_req[17] = ["TL",                     DW10,                                                                       "Transfer Length"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x82) or (admin_req[0][1] == 0x82):    # "Security Receive",
        # SQE DW 10
        admin_req[13] = ["NSFF",                     (DW10 >> 24) & 0xFF,                                                                       "NVMe Security Specific Field"]
        admin_req[14] = ["SPSP0",                     (DW10 >> 16) & 0xFF,                                                                       "SP Specific 0"]
        admin_req[15] = ["SPSP1",                     (DW10 >> 8) & 0xFF,                                                                       "SP Specific 1"]
        admin_req[16] = ["SECP",                     DW10 & 0xFF,                                                                       "Security Protocol"]
        # SQE DW 11
        admin_req[17] = ["AL",                     DW10,                                                                       "Allocation Length"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x84) or (admin_req[0][1] == 0x84):    # "Sanitize",
        # SQE DW 10
        admin_req[13] = ["SANACT",                     (DW10 & 0x07),                                                                       "Sanitize Action"]
        admin_req[14] = ["AUSE",                     bool(DW10 & 0x80),                                                                       "Allow Unrestricted Sanitize Exit"]
        admin_req[15] = ["OWPASS",                     (DW10 >> 4) & 0x0F,                                                                       "Overwrite Pass Count"]
        admin_req[16] = ["OIPBP",                     bool(DW10 & 0x100),                                                                       "Overwrite Invert Pattern Between Passes"]
        admin_req[17] = ["NDAS",                     bool(DW10 & 0x200),                                                                       "No-Deallocate After Sanitize"]
        admin_req[18] = ["EMVS",                     bool(DW10 & 0x400),                                                                       "Enter Media Verification State"]
        # SQE DW 11
        admin_req[19] = ["OVRPAT",                     DW11,                                                                       "Overwrite Pattern"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x86) or (admin_req[0][1] == 0x86):    # "Get LBA Status",
        # SQE DW 10
        admin_req[13] = ["SLBAL",                     DW10,                                                                       "Starting LBA Low"]
        # SQE DW 11
        admin_req[14] = ["SLBAU",                     DW11,                                                                       "Starting LBA Upeer"]
        # SQE DW 12
        admin_req[15] = ["MNDW",                     DW12,                                                                       "Maximum Number of Dwords"]
        # SQE DW 13
        admin_req[16] = ["RL",                     DW10 & 0xFFFF,                                                                       "Range Length"]
        admin_req[17] = ["ATYPE",                     (DW10 >> 24) & 0xFF,                                                                       "Action Type"]
    elif (admin_req[0][1] == 0x00 and LastOpcode == 0x8C) or (admin_req[0][1] == 0x8C):    # "Sanitize Namespace",
        # SQE DW 10
        admin_req[13] = ["SANACT",                     (DW10 & 0x07),                                                                       "Sanitize Action"]
        admin_req[14] = ["AUSE",                     bool(DW10 & 0x80),                                                                       "Allow Unrestricted Sanitize Exit"]
        admin_req[15] = ["EMVS",                     bool(DW10 & 0x400),                                                                       "Enter Media Verification State"]
    
    last_key = list(admin_req)[-1]

    admin_req[last_key + 1] = ["RD",                        0,                                          "Request Data"]
    if SOM == 0:
        for i in data[Offset: Offset + Len]:
            admin_req[last_key + 1][1] = i | (admin_req[last_key + 1][1] << 8)
    else:
        for i in data[64: Len]:
            admin_req[last_key + 1][1] = i | (admin_req[last_key + 1][1] << 8)
    
    return admin_req

def handle_request_pcie_command(data, firstPacket, Offset):
    return
    
def handle_request_asynchronous_event(data, firstPacket, Offset):
    return

# ------------- Response Messages
def handle_resp_ctrl_prim_parser(data, LastOpcode):
    ctrl_prim_resp = {
        0 :                 ["STA",                     data[0],                                    "Status"],
        1 :                 ["TAG",                     data[1],                                    "Tag"],
    }
    payload = data[2] | (data[3] << 8)
    
# "Pause"
    if LastOpcode == 0x00:
        # CPSR 
        ctrl_prim_resp[2] = ["PFSS0",   bool(payload & 0x01),           "Pause Flag Status Slot 0"]
        ctrl_prim_resp[3] = ["PFSS1",   bool((payload >> 1) & 0x01),    "Pause Flag Status Slot 1"]
# "Abort",
    elif LastOpcode == 0x02:
        # CPSR
        ctrl_prim_resp[2] = ['CPAS',    (payload & 0x03),               'Command Processing Abort Status']
# "Get State",
    elif LastOpcode == 0x03:
        # CPSR
        ctrl_prim_resp[2] = ["MES",     payload,                        "Management Endpoint State"]
        ctrl_prim_resp[3] = ["SSTA",    (payload & 0x03),               "       Slot Command Servicing State"]
        ctrl_prim_resp[4] = ["CMNICS",  bool((payload >> 3) & 0x01),    "       Command Message to non-Idle Command Slot"]
        ctrl_prim_resp[5] = ["BMICE",   bool((payload >> 4) & 0x01),    "       Bad Message Integrity Check Error"]
        ctrl_prim_resp[6] = ["WPTT",    bool((payload >> 5) & 0x01),    "       Timeout Waiting for a Packet"]                      #Obsolete  
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
    elif LastOpcode == 0x04:
        # CPSR
        ctrl_prim_resp[2] = ['RR',      bool(payload & 0x01),           'Response Replay']
    
    return ctrl_prim_resp

def handle_resp_nvme_mi_parser(data, Offset, Len, LastOpcode, LastDatatype, LastCID, SOM):
    nvme_mi_resp = {
        0 :                 ["STA",                     data[0],                                                        "Status"],
    }
    NVMeMngResp = data[1] | (data[2] << 8) | (data[3] << 16)

# "Read NVMe-MI Data Structure"
    if LastOpcode == 0x00:
        # NVMe Managment Response
        nvme_mi_resp[1] = ["RDL",                       (NVMeMngResp & 0xFFFF),                                         "Response Data Length"]
        if LastDatatype == 0x00:   # NVM Subsystem Information
            nvme_mi_resp[2] = ["NUMP",                  data[4],                                                        "Number of Ports"]
            nvme_mi_resp[3] = ["MJR",                   data[5],                                                        "NVMe-MI Major Version Number"]
            nvme_mi_resp[4] = ["MNR",                   data[6],                                                        "NVMe-MI Minor Version Number"]
            nvme_mi_resp[5] = ["NNSC",                  data[7],                                                        "NVMe-MI NVM Subsystem Capabilities"]
            nvme_mi_resp[6] = ["SRE",                   bool(nvme_mi_resp[5][1] & 0x1),                                 "       Status Reporting Enhancements"]
        elif LastDatatype == 0x01: # Port Information
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
        elif LastDatatype == 0x02: # Controller List
            nvme_mi_resp[2] = ["NUMCIDS",               data[4] | (data[5] << 8),                                       "Number of Controller Identifiers"]
            j = 6
            for i in range(0, nvme_mi_resp[2][1]):
                nvme_mi_resp[i + 3] = ["CID %d" % i,    data[j] | (data[j + 1] << 8),                                   "Controller Identifier %d" % i]
                j += 2
        elif LastDatatype == 0x03: # Controller Information
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
        elif LastDatatype == 0x04: # Optionally Supported Command List
                nvme_mi_resp[2] = ["NUMCMD",            data[4] | (data[5] << 8),                                       "Number of Commands"]
                j = 6
                k = 3
                for i in range(0, nvme_mi_resp[2][1]):
                    nvme_mi_resp[k] = ["CMD %d" % i,    data[j] | (data[j + 1] << 8),                                   "Command %d" % i]
                    nvme_mi_resp[k + 1] = ["NMIMT",     (nvme_mi_resp[k][1] >> 3) & 0xF,                                "       NVMe-MI Message Type"]
                    nvme_mi_resp[k + 2] = ["OPC",       (nvme_mi_resp[k][1] >> 8) & 0xFF,                               "       Opcode"]
                    j += 2
                    k += 3
        elif LastDatatype == 0x05: # Management Endpoint Buffer Command Support List
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
    elif LastOpcode == 0x01:
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
    elif LastOpcode == 0x02:
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
    elif LastOpcode == 0x03:
        if LastCID == 0x04:
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
    elif LastOpcode == 0x04:            
        if LastCID == 0x01:
            # NVMe Managment Response
            nvme_mi_resp[1] = ["SFREQ",         NVMeMngResp & 0xF,                                                      "SMBus/I2C Frequency"]
        elif LastCID == 0x03:
            # NVMe Managment Response
            nvme_mi_resp[1] = ["MTUS",          NVMeMngResp & 0xFFFF,                                                   "MCTP Transmission Unit Size"]
        elif LastCID == 0x04:
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
    elif LastOpcode == 0x05:
        # Response Data
        nvme_mi_resp[1] = ["VD",                        0,                                                              "VPD Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                nvme_mi_resp[1][1] = i | (nvme_mi_resp[1][1] << 8)
        else:
            for i in data[16: Len]:
                nvme_mi_resp[1][1] = i | (nvme_mi_resp[1][1] << 8)
# "SES Receive",
    elif LastOpcode == 0x08:
        # NVMe Managment Response
        nvme_mi_resp[1]  = ["RDL",                      NVMeMngResp & 0xFFFF,                                           "Response"]
        # Response Data
        nvme_mi_resp[2] = ["RD",                        0,                                                              "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                nvme_mi_resp[2][1] = i | (nvme_mi_resp[2][1] << 8)
        else:
            for i in data[16: Len]:
                nvme_mi_resp[2][1] = i | (nvme_mi_resp[2][1] << 8)
# "MEB Read",
    elif LastOpcode == 0x0A:
        # Response Data
        nvme_mi_resp[1] = ["MD",                        0,                                                              "MEB Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                nvme_mi_resp[1][1] = i | (nvme_mi_resp[1][1] << 8)
        else:
            for i in data[16: Len]:
                nvme_mi_resp[1][1] = i | (nvme_mi_resp[1][1] << 8)
#  "Vendor Specific"
    elif LastOpcode > 0x0C:
        # DWORD 0 (Bytes: 16 - 19)
        # DWORD 1 (Bytes: 20 - 23)
        return
    
    return nvme_mi_resp

def handle_resp_nvme_admin_command_parser(data, Offset, Len, LastOpcode, SOM):
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
    if LastOpcode == 0x02:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
# "Identify",
    elif LastOpcode == 0x06:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
# "Set Features",
    elif LastOpcode == 0x09:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Get Features",
    elif LastOpcode == 0x0A:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Namespace Management",
    elif LastOpcode == 0x0D:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Firmware Commit",
    elif LastOpcode == 0x10:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Firmware Image Download",
    elif LastOpcode == 0x11:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Device Self-Test",
    elif LastOpcode == 0x14:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Namespace attachment",
    elif LastOpcode == 0x15:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Virtualization Management",
    elif LastOpcode == 0x1C:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Capacity Management",
    elif LastOpcode == 0x20:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Lockdown",
    elif LastOpcode == 0x24:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Clear Exported NVM Resource Configuration",
    elif LastOpcode == 0x28:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Create Exported NVM Subsystem",
    elif LastOpcode == 0x2A:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Manage Exported NVM Subsystem",
    elif LastOpcode == 0x2D:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Manage Exported Namespace",
    elif LastOpcode == 0x31:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Manage Exported Port",
    elif LastOpcode == 0x35:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Format NVM",
    elif LastOpcode == 0x80:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Security Send",
    elif LastOpcode == 0x81:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Security Receive",
    elif LastOpcode == 0x82:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Sanitize",
    elif LastOpcode == 0x84:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Get LBA Status",
    elif LastOpcode == 0x86:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)    
# "Sanitize Namespace",
    elif LastOpcode == 0x8C:
        admin_resp[12] = ["RD",                        0,                                          "Response Data"]
        if SOM == 0:
            for i in data[Offset: Offset + Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)
        else:
            for i in data[16: Len]:
                admin_resp[12][1] = i | (admin_resp[12][1] << 8)        
    return admin_resp

def handle_response_pcie_command(data, firstPacket, Offset):
    return
    
def handle_response_asynchronous_event(data, firstPacket, Offset):
    return

# ------------- VPD Message

def handle_request_VPD(data):
    vpd_req = {
        0 : ['SBA',                 data[0],                        "SMBus Address"],
        1 : ['OFST',                data[1],                        "Offset"],
    }
    
    return vpd_req

def Type_Length_Byte(Field):
    # Type/Length Byte Format
    TCODE = (Field >> 6) & 0x03         # Type Code
    NDB =  (Field & 0x1F)               # Number Of Data Bytes
    
    return NDB
    
def handle_resp_vpd_parser(data):
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
            vpd_data[idx + 19][1] = Pad
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
        vpd_data[idx + 9][1], vpd_data[idx + 10][1] = UPD_FORM_FACTOR[vpd_data[idx + 8][1]]
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
                vpd_data[IdxElemc + 3][1], vpd_data[81][1] = UPD_FORM_FACTOR[vpd_data[IdxElemc + 3][1]]
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
            #TYPMap = ELEMENT_DESCRIPTOR_TYPE.get(TYP, 'Reserveed')
        idx += IdxElemc

# ------------- Basic Command Code Messages

def handle_request_BMC(data):
    BCC = {
        0 : ['SBA',                 data[0],                        "SMBus Address"],
        1 : ['CC',                data[1],                        "Command Code"],
    }
    
    return BCC
    
def handle_resp_bmc_cc_parser(data):
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
    SN = ""
    for i in range(11, 30):
        #cc_response[19][1] = data[i] | (cc_response[19][1] << 8)
        SN = SN + "".join(chr(int(data[i])))
    for i in range(32, 255):
        cc_response[21][1] = data[i] | (cc_response[21][1] << 8)

    cc_response[19][1] = SN
    return cc_response