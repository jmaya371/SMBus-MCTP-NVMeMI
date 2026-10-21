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
from .Dictionaries import *
import struct
# ============================================================
# Tables / Constants
# ============================================================

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
        self.LastCID = 0
        self.LastDytp = 0
        self.LastOpcode = 0
        self.SOM = 1
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

    def handle_smbus(self):
        Data = [self.packets[j][3] for j in range(0, 4)]
        smbus = handle_smbus_parser(Data)

        self.put(self.packets[0][0], self.packets[3][1], self.out_ann, [12, ['SMBus header ', 'SMBus header', 'SBH']])
        self.put(self.packets[0][0], self.packets[3][1], self.out_ann, [3, 
        ['%s: %02X | %s: %02X | %s: %02X | %s: %02X' % (smbus[0][2], smbus[0][1], smbus[1][2], smbus[1][1], smbus[2][2], smbus[2][1], smbus[3][2], smbus[3][1]), 
        '%s: %02X | %s: %02X | %s: %02X | %s: %02X' % (smbus[0][0], smbus[0][1], smbus[1][0], smbus[1][1], smbus[2][0], smbus[2][1], smbus[3][0], smbus[3][1]), 
        '%s | %s | %s | %s' % (smbus[0][0], smbus[1][0], smbus[2][0], smbus[3][0]), 
        'S']])
        
    def handle_mctp(self):
        Data = [self.packets[j][3] for j in range(4, 8)]
        mctp = handle_mctp_parser(Data)
        
        self.SOM = mctp[4][1]
        self.EOM = mctp[5][1]
        
        self.put(self.packets[4][0], self.packets[7][1], self.out_ann, [13, ['MCTP Header', 'MCTP', 'MH']])
        self.put(self.packets[4][0], self.packets[7][1], self.out_ann, [4, 
        ['%s: %02X | %s: %02X → %s %02X | %s %r %s %r %s %02X %s %d %s %02X' % (mctp[0][2], mctp[0][1], mctp[1][2], mctp[1][1], mctp[2][2], mctp[2][1], mctp[4][2], mctp[4][1], mctp[5][2], mctp[5][1], mctp[6][2], mctp[6][1], mctp[7][2], mctp[7][1], mctp[8][2], mctp[8][1]), 
        '%s: %02X | %s: %02X → %s %02X | %s %r %s %r %s %02X %s %d %s %02X' % (mctp[0][0], mctp[0][1], mctp[1][0], mctp[1][1], mctp[2][0], mctp[2][1], mctp[4][0], mctp[4][1], mctp[5][0], mctp[5][1], mctp[6][0], mctp[6][1], mctp[7][0], mctp[7][1], mctp[8][0], mctp[8][1]), 
        '%s | %s → %s | %s' % (mctp[0][0], mctp[1][0], mctp[2][0], mctp[3][0]), 
        'Mc']])

    def handle_mi(self):
        Data = [self.packets[j][3] for j in range(8, 12)]
        nvme = handle_mi_parser(Data)
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
        s = 'handle_request_%s' % self.msgMiType.lower().replace(' ', '_')
        handle_state = getattr(self, s)
        handle_state(data, firstPacket, Offset)

    def handle_mi_payload_response(self, data, firstPacket, Offset):
        SizeData = len(data)
        s = 'handle_response_%s' % self.msgMiType.lower().replace(' ', '_')
        handle_state = getattr(self, s)
        handle_state(data, firstPacket, Offset)

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

# ------------- Request Messages

    def handle_request_control_primitive(self, data, firstPacket, Offset):
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data + [0 for i in range(len(Payload), 4224)]
        
        if self.SOM == 1 :
            self.LastOpcode = Payload[0]
        else:
            Payload[0] = self.LastOpcode
            
        ctrl_prim = handle_req_ctrl_prim_parser(Payload)
        CtrlPrim = NVME_CONTROL_OPCODES.get(ctrl_prim[0][1], 'Reserved')
            
        CtrlPrimReq = {
            0 :[12, 4, [14, ['Control Primitive Request', 'Ctrl Prim Rqst', 'CRQ']]],
            1 :[],
        }

    # "Get State",
        if self.LastOpcode == 0x03:
            CtrlPrimReq[1] = [12, 4, [4, ['%s: %s | %s: %02X | %s: %r' % (ctrl_prim[0][2], CtrlPrim, ctrl_prim[1][2], ctrl_prim[1][1], ctrl_prim[2][2], ctrl_prim[2][1]), '%s: %s | %s: %02X | %s: %r' % (ctrl_prim[0][0], CtrlPrim, ctrl_prim[1][0], ctrl_prim[1][1], ctrl_prim[2][0], ctrl_prim[2][1]), '%s | %s | %s' % (ctrl_prim[0][0], ctrl_prim[1][0], ctrl_prim[2][0]), 'CPP']]]
    # "Replay",
        elif self.LastOpcode == 0x04:
            CtrlPrimReq[1] = [12, 4, [4, ['%s: %s | %s: %02X | %s: %02X' % (ctrl_prim[0][2], CtrlPrim, ctrl_prim[1][2], ctrl_prim[1][1], ctrl_prim[2][2], ctrl_prim[2][1]), '%s: %s | %s: %02X | %s: %02X' % (ctrl_prim[0][0], CtrlPrim, ctrl_prim[1][0], ctrl_prim[1][1], ctrl_prim[2][0], ctrl_prim[2][1]), '%s | %s | %s' % (ctrl_prim[0][0], ctrl_prim[1][0], ctrl_prim[2][0]), 'CPP']]]
    # "Pause", "Resume", "Abort",
        elif self.LastOpcode < 0x03:           
            CtrlPrimReq[1] = [12, 4, [4, ['%s: %s | %s: %02X' % (ctrl_prim[0][2], CtrlPrim, ctrl_prim[1][2], ctrl_prim[1][1]), '%s: %s | %s: %02X' % (ctrl_prim[0][0], CtrlPrim, ctrl_prim[1][0], ctrl_prim[1][1]), '%s | %s' % (ctrl_prim[0][0], ctrl_prim[1][0]), 'CP']]]

        Cnt = firstPacket
        for Idx, value in list(CtrlPrimReq.items())[::2]:
            if CtrlPrimReq[Idx][0] >= (Offset + firstPacket) or CtrlPrimReq[Idx][1] > Offset :
                if (Cnt + CtrlPrimReq[Idx][1]) < (firstPacket + len(data)):
                    self.put(self.packets[Cnt][0], self.packets[Cnt + CtrlPrimReq[Idx][1] - 1][1], self.out_ann, CtrlPrimReq[Idx][2])
                    self.put(self.packets[Cnt][0], self.packets[Cnt + CtrlPrimReq[Idx][1] - 1][1], self.out_ann, CtrlPrimReq[Idx + 1][2])
                    Cnt += CtrlPrimReq[Idx][1]
                else:
                    self.put(self.packets[Cnt][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, CtrlPrimReq[Idx][2])
                    self.put(self.packets[Cnt][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, CtrlPrimReq[Idx + 1][2])
                    Cnt += len(data)

    def handle_request_nvme_mi_command(self, data, firstPacket, Offset):
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data + [0 for i in range(len(Payload), 4224)]
        Data = [self.packets[j][3] for j in range(12, len(self.packets))]
        
        if self.SOM == 1 :
            self.LastOpcode = Payload[0]
        else:
            Payload[0] = self.LastOpcode
        
        nvme_mi_req = handle_req_nvme_mi_parser(Payload)
        NVMe_Mi = NVME_MI_OPCODES.get(nvme_mi_req[0][1], "Reserved")
        
        NvmeMiReq = {
            0 :[12, 4, [14, ['Opcode', 'Opc', 'O']]],
            1 :[12, 4, [3, ["NVMe MI command: %s" % NVMe_Mi, 'MI command: %s' % NVMe_Mi, 'Opc: %02X' % nvme_mi_req[0][1], 'opc']]],
            2 :[16, 4, [14, ['DWORD 0', 'DW 0', 'D0']]],
            3 :[],
            4 :[16, 4, [14, ['DWORD 0', 'DW 0', 'D0']]],
            5 :[],
        }

    # "Read NVMe-MI Data Structure",
        if self.LastOpcode == 0x00:
            self.LastDytp = nvme_mi_req[3][1]
            NvmeMiReq[3] = [16, 4, [4, ['%s: %04X | %s: %02X | %s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1]), '%s: %04X | %s: %02X | %s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1]), '%s | %s | %s' %(nvme_mi_req[1][0], nvme_mi_req[2][0], nvme_mi_req[3][0]), 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['%s: %02X' % (nvme_mi_req[4][2], nvme_mi_req[4][1]), '%s: %02X' % (nvme_mi_req[4][0], nvme_mi_req[4][1]),'%s' % nvme_mi_req[4][0], 'DW1']]]
    # "NVM Subsystem Health Status Poll",
        elif self.LastOpcode == 0x01:
            NvmeMiReq[3] = [16, 4, [4, ['Reserved: 00 00 00 00', 'RSVD: 00 00 00 00', 'RSVD', 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['%s: %r' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %r' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW1']]]
    # "Controller Health Status Poll",
        elif self.LastOpcode == 0x02:
            NvmeMiReq[3] = [16, 4, [3, ['%s: %04X | %s: %02X | %s: %r | %s: %r | %s: %r | %s: %r' %(nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1], nvme_mi_req[4][2], nvme_mi_req[4][1], nvme_mi_req[5][2], nvme_mi_req[5][1], nvme_mi_req[6][2], nvme_mi_req[6][1]), '%s: %04X | %s: %02X | %s: %r | %s: %r | %s: %r | %s: %r' %(nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1], nvme_mi_req[4][0], nvme_mi_req[4][1], nvme_mi_req[5][0], nvme_mi_req[5][1], nvme_mi_req[6][0], nvme_mi_req[6][1]), '%s | %s | %s | %s | %s | %s' %(nvme_mi_req[1][0], nvme_mi_req[2][0], nvme_mi_req[3][0], nvme_mi_req[4][0], nvme_mi_req[5][0], nvme_mi_req[6][0]), 'DW0']]]
            NvmeMiReq[5] = [20, 4, [3, ['%s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r' %(nvme_mi_req[7][2], nvme_mi_req[7][1], nvme_mi_req[8][2], nvme_mi_req[8][1], nvme_mi_req[9][2], nvme_mi_req[9][1], nvme_mi_req[10][2], nvme_mi_req[10][1], nvme_mi_req[11][2], nvme_mi_req[11][1], nvme_mi_req[12][2], nvme_mi_req[12][1]), '%s: %04X | %s: %02X | %s: %r | %s: %r | %s: %r | %s: %r' %(nvme_mi_req[7][0], nvme_mi_req[7][1], nvme_mi_req[8][0], nvme_mi_req[8][1], nvme_mi_req[9][0], nvme_mi_req[9][1], nvme_mi_req[10][0], nvme_mi_req[10][1], nvme_mi_req[11][0], nvme_mi_req[11][1], nvme_mi_req[12][0], nvme_mi_req[12][1]), '%s | %s | %s | %s | %s | %s' %(nvme_mi_req[7][0], nvme_mi_req[8][0], nvme_mi_req[9][0], nvme_mi_req[10][0], nvme_mi_req[11][0], nvme_mi_req[12][0]), 'DW0']]]
    # "Configuration Set",
        elif self.LastOpcode == 0x03:
            self.LastCID = nvme_mi_req[1][1]
            if nvme_mi_req[1][1] == 0x01:
                NvmeMiReq[3] = [16, 4, [4, ['%s: %02X | %s: %02X | %s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1]), '%s: %02X | %s: %02X | %s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1]), '%s | %s | %s' % (nvme_mi_req[1][0], nvme_mi_req[2][0], nvme_mi_req[3][0]), 'DW0']]]
                NvmeMiReq[5] = [20, 4, [4, ['Reserved: 00 00 00 00', 'RSVD: 00 00 00 00', 'RSVD', 'DW1']]]
            elif nvme_mi_req[1][1] == 0x02:
                NvmeMiReq[3] = [16, 4, [4, ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
                NvmeMiReq[5] = [20, 4, [3, ['%s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d' % (nvme_mi_req[10][2], nvme_mi_req[10][1], nvme_mi_req[11][2], nvme_mi_req[11][1], nvme_mi_req[12][2], nvme_mi_req[12][1], nvme_mi_req[13][2], nvme_mi_req[13][1], nvme_mi_req[14][2], nvme_mi_req[14][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1], nvme_mi_req[4][2], nvme_mi_req[4][1], nvme_mi_req[5][2], nvme_mi_req[5][1], nvme_mi_req[6][2], nvme_mi_req[6][1], nvme_mi_req[7][2], nvme_mi_req[7][1], nvme_mi_req[8][2], nvme_mi_req[8][1], nvme_mi_req[9][2], nvme_mi_req[9][1]),'%s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d | %s: %d' % (nvme_mi_req[10][0], nvme_mi_req[10][1], nvme_mi_req[11][0], nvme_mi_req[11][1], nvme_mi_req[12][0], nvme_mi_req[12][1], nvme_mi_req[13][0], nvme_mi_req[13][1], nvme_mi_req[14][0], nvme_mi_req[14][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1], nvme_mi_req[4][0], nvme_mi_req[4][1], nvme_mi_req[5][0], nvme_mi_req[5][1], nvme_mi_req[6][0], nvme_mi_req[6][1], nvme_mi_req[7][0], nvme_mi_req[7][1], nvme_mi_req[8][0], nvme_mi_req[8][1], nvme_mi_req[9][0], nvme_mi_req[9][1]),'%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' % (nvme_mi_req[10][0], nvme_mi_req[11][0], nvme_mi_req[12][0], nvme_mi_req[13][0], nvme_mi_req[14][0], nvme_mi_req[2][0], nvme_mi_req[3][0], nvme_mi_req[4][0], nvme_mi_req[5][0], nvme_mi_req[6][0], nvme_mi_req[7][0], nvme_mi_req[8][0], nvme_mi_req[9][0]),'bits (12 - 0) %d %d %d %d %d %d %d %d %d %d %d %d %d' % (nvme_mi_req[10][1], nvme_mi_req[11][1], nvme_mi_req[12][1], nvme_mi_req[13][1], nvme_mi_req[14][1], nvme_mi_req[2][1], nvme_mi_req[3][1], nvme_mi_req[4][1], nvme_mi_req[5][1], nvme_mi_req[6][1], nvme_mi_req[7][1], nvme_mi_req[8][1], nvme_mi_req[9][1]),'DW1']]]
            elif nvme_mi_req[1][1] == 0x03:
                NvmeMiReq[3] = [16, 4, [4, ['%s: %02X | %s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1]), '%s: %02X | %s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1]), '%s | %s' % (nvme_mi_req[1][0], nvme_mi_req[2][0]), 'DW0']]]
                NvmeMiReq[5] = [20, 4, [4, ['%s: %04X' % (nvme_mi_req[3][2], nvme_mi_req[3][1]), '%s: %04X' % (nvme_mi_req[3][0], nvme_mi_req[3][1]),'%s' % nvme_mi_req[3][0], 'DW1']]]
            elif nvme_mi_req[1][1] == 0x04:
                NvmeMiReq[3] = [16, 4, [4, ['%s: %02X | Async Event ► %s: %02X → %s: %02X → %s: %r → %s: %r → %s: %r' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1], nvme_mi_req[3][2], nvme_mi_req[3][1], nvme_mi_req[4][2], nvme_mi_req[4][1], nvme_mi_req[5][2], nvme_mi_req[5][1], nvme_mi_req[6][2], nvme_mi_req[6][1]), '%s: %02X | %s: %02X → %s: %02X → %s: %r → %s: %r → %s: %r' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1], nvme_mi_req[3][0], nvme_mi_req[3][1], nvme_mi_req[4][0], nvme_mi_req[4][1], nvme_mi_req[5][0], nvme_mi_req[5][1], nvme_mi_req[6][0], nvme_mi_req[6][1]), '%s | %s → %s → %s → %s → %s' % (nvme_mi_req[1][0], nvme_mi_req[2][0], nvme_mi_req[3][0], nvme_mi_req[4][0], nvme_mi_req[5][0], nvme_mi_req[6][0]), 'DW0']]]
                NvmeMiReq[5] = [20, 4, [4, ['Reserved: 00 00 00 00', 'RSVD: 00 00 00 00', '00 00 00 00', 'DW1']]]
                if len(Data) > 17:
                    # Request Data                
                    NvmeMiReq[6] = [24, 5, [14, ['AE Enable List Header', 'AE List', 'AE']]]
                    NvmeMiReq[7] = [24, 5, [4, ['%s: %02X | %s: %02X | %s: %04X | %s: %02X' % (nvme_mi_req[7][2], nvme_mi_req[7][1], nvme_mi_req[8][2], nvme_mi_req[8][1], nvme_mi_req[9][2], nvme_mi_req[9][1], nvme_mi_req[10][2], nvme_mi_req[10][1]), '%s: %02X | %s: %02X | %s: %04X | %s: %02X' % (nvme_mi_req[7][0], nvme_mi_req[7][1], nvme_mi_req[8][0], nvme_mi_req[8][1], nvme_mi_req[9][0], nvme_mi_req[9][1], nvme_mi_req[10][0], nvme_mi_req[10][1]), '%s | %s | %s | %s' % (nvme_mi_req[7][0], nvme_mi_req[8][0], nvme_mi_req[9][0], nvme_mi_req[10][0]), 'AE']]]                
                    j = 29
                    k = 11
                    m = 8
                    for i in range(0, nvme_mi_req[7][1]):
                        NvmeMiReq[m] = [j, 3, [14, ['AE Enable Data Structure %d' % i, 'AE Ena DS %d' % i, 'AE%d' % i]]]
                        NvmeMiReq[m + 2] = [j, 3, [4, ['%s ► %s: %02X → %s: %02X → %s: %r' % (nvme_mi_req[k][2], nvme_mi_req[k + 1][2], nvme_mi_req[k + 1][1], nvme_mi_req[k + 2][2], nvme_mi_req[k + 2][1], nvme_mi_req[k + 3][2], nvme_mi_req[k + 3][1]), '%s ► %s: %02X → %s: %02X → %s: %r' % (nvme_mi_req[k][0], nvme_mi_req[k + 1][0], nvme_mi_req[k + 1][1], nvme_mi_req[k + 2][0], nvme_mi_req[k + 2][1], nvme_mi_req[k + 3][0], nvme_mi_req[k + 3][1]), '%s ► %s → %s → %s' % (nvme_mi_req[k][0], nvme_mi_req[k + 1][0], nvme_mi_req[k + 2][0], nvme_mi_req[k + 3][0]), 'DS']]]
                        j += 3
                        k += 4
    # "Configuration Get",
        elif self.LastOpcode == 0x04:
            self.LastCID = nvme_mi_req[1][1]
            if nvme_mi_req[1][1] == 0x01 or nvme_mi_req[1][1] == 0x03:
                NvmeMiReq[3] = [16, 4, [4, ['%s: %02X | %s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1], nvme_mi_req[2][2], nvme_mi_req[2][1]), '%s: %02X | %s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1], nvme_mi_req[2][0], nvme_mi_req[2][1]), '%s | %s' %(nvme_mi_req[1][0], nvme_mi_req[2][0]), 'DW0']]]
            else:
                NvmeMiReq[3] = [16, 4, [4, ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['Reserved: 00 00 00 00', 'RSVD: 00 00 00 00', '00 00 00 00', 'DW1']]]
    # "VPD Read",
        elif self.LastOpcode == 0x05:
            NvmeMiReq[3] = [16, 4, [4, ['%s: %04X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %04X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),'%s' % nvme_mi_req[2][0], 'DW1']]]
    # "VPD Write",
        elif self.LastOpcode == 0x06:
            NvmeMiReq[3] = [16, 4, [4, ['%s: %04X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %04X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),'%s' % nvme_mi_req[2][0], 'DW1']]]
            NvmeMiReq[6] = [24, 255, [14, ['Request Data', 'Req Data', 'RQ']]]
            NvmeMiReq[7] = [24, 255, [4, ['%s: %X' % (nvme_mi_req[3][2], nvme_mi_req[3][1]), '%s: %X' % (nvme_mi_req[3][0], nvme_mi_req[3][1]), '%s' % nvme_mi_req[3][0], 'RD']]]
    # "Reset",
        elif self.LastOpcode == 0x07:
            NvmeMiReq[3] = [16, 4, [4, ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['Reserved: 00 00 00 00', 'RSVD: 00 00 00 00', 'RSVD', 'DW1']]]
    # "SES Receive",
        elif self.LastOpcode == 0x08:
            NvmeMiReq[3] = [16, 4, [4, ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),'%s' % nvme_mi_req[2][0], 'DW1']]]
    # "SES Send",
        elif self.LastOpcode == 0x09:
            NvmeMiReq[3] = [16, 4, [4, ['Reserved: 00 00 00 00', 'RSVD: 00 00 00 00', 'RSVD', 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW1']]]
            NvmeMiReq[6] = [24, 255, [14, ['Request Data', 'Req Data', 'RQ']]]
            NvmeMiReq[7] = [24, 255, [4, ['%s: %X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), '%s: %X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),'%s' % nvme_mi_req[2][0], 'RQ']]]
    # "MEB Read",
        elif self.LastOpcode == 0x0A:
            NvmeMiReq[3] = [16, 4, [4, ['%s: %08X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %08X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),'%s' % nvme_mi_req[2][0], 'DW1']]]
    # "MEB Write",
        elif self.LastOpcode == 0x0B:  
            NvmeMiReq[3] = [16, 4, [4, ['%s: %08X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %08X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['%s: %04X' % (nvme_mi_req[2][2], nvme_mi_req[2][1]), '%s: %04X' % (nvme_mi_req[2][0], nvme_mi_req[2][1]),'%s' % nvme_mi_req[2][0], 'DW1']]]
            NvmeMiReq[6] = [24, 255, [14, ['Request Data', 'Req Data', 'RQ']]]
            NvmeMiReq[7] = [24, 255, [4, ['%s: %X' % (nvme_mi_req[3][2], nvme_mi_req[3][1]), '%s: %X' % (nvme_mi_req[3][0], nvme_mi_req[3][1]), '%s' % nvme_mi_req[3][0], 'RD']]]
    # "Shutdown",
        elif self.LastOpcode == 0x0C:
            NvmeMiReq[3] = [16, 4, [4, ['%s: %02X' % (nvme_mi_req[1][2], nvme_mi_req[1][1]), '%s: %02X' % (nvme_mi_req[1][0], nvme_mi_req[1][1]),'%s' % nvme_mi_req[1][0], 'DW0']]]
            NvmeMiReq[5] = [20, 4, [4, ['Reserved: 00 00 00 00', 'RSVD: 00 00 00 00', 'RSVD', 'DW1']]]
    #  "Vendor Specific"
        elif self.LastOpcode > 0x0C:
            # DWORD 0 (Bytes: 16 - 19)
            # DWORD 1 (Bytes: 20 - 23)
            return

        Cnt = firstPacket
        for Idx, value in list(NvmeMiReq.items())[::2]:
            if NvmeMiReq[Idx][0] >= (Offset + firstPacket) or NvmeMiReq[Idx][1] > Offset :
                if (Cnt + NvmeMiReq[Idx][1]) < (firstPacket + len(data)):
                    self.put(self.packets[Cnt][0], self.packets[Cnt + NvmeMiReq[Idx][1] - 1][1], self.out_ann, NvmeMiReq[Idx][2])
                    self.put(self.packets[Cnt][0], self.packets[Cnt + NvmeMiReq[Idx][1] - 1][1], self.out_ann, NvmeMiReq[Idx + 1][2])
                    Cnt += NvmeMiReq[Idx][1]
                else:
                    self.put(self.packets[Cnt][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, NvmeMiReq[Idx][2])
                    self.put(self.packets[Cnt][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, NvmeMiReq[Idx + 1][2])
                    Cnt += len(data)
        
    def handle_request_nvme_admin_command(self, data, firstPacket, Offset):
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data + [0 for i in range(len(Payload), 4224)]
        admin_req = handle_req_nvme_admin_parser(Payload, Offset, len(data))
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

    def handle_request_pcie_command(self, data, firstPacket, Offset):
        return
        
    def handle_request_asynchronous_event(self, data, firstPacket, Offset):
        return

# ------------- Response Messages

    def handle_response_control_primitive(self, data, firstPacket, Offset):
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data + [0 for i in range(len(Payload), 4224)]
        ctrl_prim_resp = handle_resp_ctrl_prim_parser(Payload, self.LastOpcode)

        NVMeMiStatus = NVME_MI_STATUS.get(ctrl_prim_resp[0][1], 'Reserved')
        CtrlPrimResp = {
            0 :[12, 4, [14, ['Control Primitive Response', 'Ctrl Prim Resp', 'CRP']]],
            1 :[],
        }

    # "Pause"
        if self.LastOpcode == 0x00:
            CtrlPrimResp[1] = [12, 4, [4, ['%s: %s | %s: %02X | %s: %r | %s: %r' % (ctrl_prim_resp[0][2], NVMeMiStatus, ctrl_prim_resp[1][2], ctrl_prim_resp[1][1], ctrl_prim_resp[2][2], ctrl_prim_resp[2][1], ctrl_prim_resp[3][2], ctrl_prim_resp[3][1]), '%s: %s | %s: %02X | %s: %r | %s: %r' % (ctrl_prim_resp[0][0], NVMeMiStatus, ctrl_prim_resp[1][0], ctrl_prim_resp[1][1], ctrl_prim_resp[2][0], ctrl_prim_resp[2][1], ctrl_prim_resp[3][0], ctrl_prim_resp[3][1]), '%s | %s | %s | %s' % (ctrl_prim_resp[0][0], ctrl_prim_resp[1][0], ctrl_prim_resp[2][0], ctrl_prim_resp[3][0]), 'CPP']]]
    # "Resume",
        elif self.LastOpcode == 0x01:
            CtrlPrimResp[1] = [12, 4, [4, ['%s: %s | %s: %02X' % (ctrl_prim_resp[0][2], NVMeMiStatus, ctrl_prim_resp[1][2], ctrl_prim_resp[1][1]), '%s: %s | %s: %02X' % (ctrl_prim_resp[0][0], NVMeMiStatus, ctrl_prim_resp[1][0], ctrl_prim_resp[1][1]), '%s | %s' % (ctrl_prim_resp[0][0], ctrl_prim_resp[1][0]), 'CPP']]]
    # "Abort",
        elif self.LastOpcode == 0x02:
            CtrlPrimResp[1] = [12, 4, [4, ['%s: %s | %s: %02X | %s: %d' % (ctrl_prim_resp[0][2], NVMeMiStatus, ctrl_prim_resp[1][2], ctrl_prim_resp[1][1], ctrl_prim_resp[2][2], ctrl_prim_resp[2][1]), '%s: %s | %s: %02X | %s: %d' % (ctrl_prim_resp[0][0], NVMeMiStatus, ctrl_prim_resp[1][0], ctrl_prim_resp[1][1], ctrl_prim_resp[2][0], ctrl_prim_resp[2][1]), '%s | %s | %s' % (ctrl_prim_resp[0][0], ctrl_prim_resp[1][0], ctrl_prim_resp[2][0]), 'CPP']]]
    # "Get State",
        elif self.LastOpcode == 0x03:
            CtrlPrimResp[1] = [12, 4, [4, ['%s: %s | %s: %02X | %s: %d | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r | %s: %r' % (ctrl_prim_resp[0][2], NVMeMiStatus, ctrl_prim_resp[1][2], ctrl_prim_resp[1][1], ctrl_prim_resp[3][2], ctrl_prim_resp[3][1], ctrl_prim_resp[4][2], ctrl_prim_resp[4][1], ctrl_prim_resp[5][2], ctrl_prim_resp[5][1], ctrl_prim_resp[6][2], ctrl_prim_resp[6][1], ctrl_prim_resp[7][2], ctrl_prim_resp[7][1], ctrl_prim_resp[8][2], ctrl_prim_resp[8][1], ctrl_prim_resp[9][2], ctrl_prim_resp[9][1], ctrl_prim_resp[10][2], ctrl_prim_resp[10][1], ctrl_prim_resp[11][2], ctrl_prim_resp[11][1], ctrl_prim_resp[12][2], ctrl_prim_resp[12][1], ctrl_prim_resp[13][2], ctrl_prim_resp[13][1], ctrl_prim_resp[14][1], ctrl_prim_resp[14][1],ctrl_prim_resp[15][2], ctrl_prim_resp[15][1], ctrl_prim_resp[16][2], ctrl_prim_resp[16][1]),  '%s| %s: %02X | %s: %04X' % (ctrl_prim_resp[0][0], NVMeMiStatus, ctrl_prim_resp[1][0], ctrl_prim_resp[1][1], ctrl_prim_resp[2][0], ctrl_prim_resp[2][1]),'%s | %s | %s' % (ctrl_prim_resp[0][0], ctrl_prim_resp[1][0], ctrl_prim_resp[2][0]),  'CPP']]]
    # "Replay",
        elif self.LastOpcode == 0x04:
            CtrlPrimResp[1] = [12, 4, [4, ['%s: %s | %s: %02X | %s: %r' % (ctrl_prim_resp[0][2], NVMeMiStatus, ctrl_prim_resp[1][2], ctrl_prim_resp[1][1], ctrl_prim_resp[2][2], ctrl_prim_resp[2][1]), '%s: %s | %s: %02X | %s: %r' % (ctrl_prim_resp[0][0], NVMeMiStatus, ctrl_prim_resp[1][0], ctrl_prim_resp[1][1], ctrl_prim_resp[2][0], ctrl_prim_resp[2][1]), '%s | %s | %s' % (ctrl_prim_resp[0][0], ctrl_prim_resp[1][0], ctrl_prim_resp[2][0]), 'CPP']]]

        Cnt = firstPacket
        for Idx, value in list(CtrlPrimResp.items())[::2]:
            if CtrlPrimResp[Idx][0] >= (Offset + firstPacket) or CtrlPrimResp[Idx][1] > Offset :
                if (Cnt + CtrlPrimResp[Idx][1]) < (firstPacket + len(data)):
                    self.put(self.packets[Cnt][0], self.packets[Cnt + CtrlPrimResp[Idx][1] - 1][1], self.out_ann, CtrlPrimResp[Idx][2])
                    self.put(self.packets[Cnt][0], self.packets[Cnt + CtrlPrimResp[Idx][1] - 1][1], self.out_ann, CtrlPrimResp[Idx + 1][2])
                    Cnt += CtrlPrimResp[Idx][1]
                else:
                    self.put(self.packets[Cnt][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, CtrlPrimResp[Idx][2])
                    self.put(self.packets[Cnt][0], self.packets[firstPacket + len(data) - 1][1], self.out_ann, CtrlPrimResp[Idx + 1][2])
                    Cnt += len(data)

    def handle_response_nvme_mi_command(self, data, firstPacket, Offset):          
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data
        Payload.extend([0 for i in range(len(Payload), 4224)])
        nvme_mi_resp = handle_resp_nvme_mi_parser(Payload, Offset, len(data), self.LastOpcode, self.LastDytp, self.LastCID, self.SOM)
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

    def handle_response_nvme_admin_command(self, data, firstPacket, Offset):
        Payload = []
        Payload = [0 for i in range(0, Offset)] + data
        Payload.extend([0 for i in range(len(Payload), 4224)])
        admin_resp = handle_resp_nvme_admin_command_parser(Payload, Offset, len(data), self.LastOpcode)
        #NVMeMiStatus = NVME_MI_STATUS.get(admin_resp[0][1], 'Reserveed')
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

    def handle_response_pcie_command(self, data, firstPacket, Offset):
        return
        
    def handle_response_asynchronous_event(self, data, firstPacket, Offset):
        return


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

# ------------- VPD Message

    def handle_request_VPD(self):
        SMBusAddr = self.packets[0][3]
        Offset = self.packets[1][3]
        self.put(self.packets[0][0], self.packets[1][1], self.out_ann, [3, 
        ['SMBusAddr: %02X | Offset: %02X' % (SMBusAddr, Offset), 
        '%02X | %02X' % (SMBusAddr, Offset), 
        'SMBusAddr|Offset', 
        'CC']])
        self.put(self.packets[0][0], self.packets[1][1], self.out_ann, [12, ['VPD Read w/offset: %02X' % Offset, 'VPD Read', 'VPD']])
        
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

# ------------- Basic Command Code Messages

    def handle_request_BMC(self):
        SMBusAddr = self.packets[0][3]
        CmdCode = self.packets[1][3]
        self.put(self.packets[0][0], self.packets[1][1], self.out_ann, [3, 
        ['SMBusAddr: %02X | Command Code: %02X' % (SMBusAddr, CmdCode), 
        '%02X | %02X' % (SMBusAddr, CmdCode), 
        'SMBusAddr|CmdCode', 
        'CC']])
        self.put(self.packets[0][0], self.packets[1][1], self.out_ann, [12, ['Command Code', 'CC', 'CC']])
        
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
        cc_response = handle_resp_bmc_cc_parser(Data)

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
