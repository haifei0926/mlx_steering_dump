# Copyright (c) 2020 Mellanox Technologies, Inc.  All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import ctypes
import re
from  enum import Enum
from src.dr_prettify import pretty_ip, pretty_mac

# sw steering dump tool version
g_version = "1.0.1"
g_indent = 0
TAB = "   "
COLORED_PRINTS = False

class MLX5_MOD_FLD(Enum):
    MLX5_MODI_OUT_NONE = -1
    MLX5_MODI_OUT_SMAC_47_16 = 1
    MLX5_MODI_OUT_SMAC_15_0 = 2
    MLX5_MODI_OUT_ETHERTYPE = 3
    MLX5_MODI_OUT_DMAC_47_16 = 4
    MLX5_MODI_OUT_DMAC_15_0 = 5
    MLX5_MODI_OUT_IP_DSCP = 6
    MLX5_MODI_OUT_TCP_FLAGS = 7
    MLX5_MODI_OUT_TCP_SPORT = 8
    MLX5_MODI_OUT_TCP_DPORT = 9
    MLX5_MODI_OUT_IPV4_TTL = 10
    MLX5_MODI_OUT_UDP_SPORT = 11
    MLX5_MODI_OUT_UDP_DPORT = 12
    MLX5_MODI_OUT_SIPV6_127_96 = 13
    MLX5_MODI_OUT_SIPV6_95_64 = 14
    MLX5_MODI_OUT_SIPV6_63_32 = 15
    MLX5_MODI_OUT_SIPV6_31_0 = 16
    MLX5_MODI_OUT_DIPV6_127_96 = 17
    MLX5_MODI_OUT_DIPV6_95_64 = 18
    MLX5_MODI_OUT_DIPV6_63_32 = 19
    MLX5_MODI_OUT_DIPV6_31_0 = 20
    MLX5_MODI_OUT_SIPV4 = 21
    MLX5_MODI_OUT_DIPV4 = 22
    MLX5_MODI_OUT_FIRST_VID = 23
    MLX5_MODI_IN_SMAC_47_16 = 0x31
    MLX5_MODI_IN_SMAC_15_0 = 0x32
    MLX5_MODI_IN_ETHERTYPE = 0x33
    MLX5_MODI_IN_DMAC_47_16 = 0x34
    MLX5_MODI_IN_DMAC_15_0 = 0x35
    MLX5_MODI_IN_IP_DSCP = 0x36
    MLX5_MODI_IN_TCP_FLAGS = 0x37
    MLX5_MODI_IN_TCP_SPORT = 0x38
    MLX5_MODI_IN_TCP_DPORT = 0x39
    MLX5_MODI_IN_IPV4_TTL = 0x3a
    MLX5_MODI_IN_UDP_SPORT = 0x3b
    MLX5_MODI_IN_UDP_DPORT = 0x3c
    MLX5_MODI_IN_SIPV6_127_96 = 0x3d
    MLX5_MODI_IN_SIPV6_95_64 = 0x3e
    MLX5_MODI_IN_SIPV6_63_32 = 0x3f
    MLX5_MODI_IN_SIPV6_31_0 = 0x40
    MLX5_MODI_IN_DIPV6_127_96 = 0x41
    MLX5_MODI_IN_DIPV6_95_64 = 0x42
    MLX5_MODI_IN_DIPV6_63_32 = 0x43
    MLX5_MODI_IN_DIPV6_31_0 = 0x44
    MLX5_MODI_IN_SIPV4 = 0x45
    MLX5_MODI_IN_DIPV4 = 0x46
    MLX5_MODI_OUT_IPV6_HOPLIMIT = 0x47
    MLX5_MODI_IN_IPV6_HOPLIMIT = 0x48
    MLX5_MODI_META_DATA_REG_A = 0x49
    MLX5_MODI_META_DATA_REG_B = 0x50
    MLX5_MODI_META_REG_C_0 = 0x51
    MLX5_MODI_META_REG_C_1 = 0x52
    MLX5_MODI_META_REG_C_2 = 0x53
    MLX5_MODI_META_REG_C_3 = 0x54
    MLX5_MODI_META_REG_C_4 = 0x55
    MLX5_MODI_META_REG_C_5 = 0x56
    MLX5_MODI_META_REG_C_6 = 0x57
    MLX5_MODI_META_REG_C_7 = 0x58
    MLX5_MODI_OUT_TCP_SEQ_NUM = 0x59
    MLX5_MODI_IN_TCP_SEQ_NUM = 0x5a
    MLX5_MODI_OUT_TCP_ACK_NUM = 0x5b
    MLX5_MODI_IN_TCP_ACK_NUM = 0x5c
    MLX5_MODI_GTP_TEID = 0x6e

class _data0(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32, 5),
               ('rsvd0', ctypes.c_uint32, 3),
               ('offset', ctypes.c_uint32, 5),
               ('rsvd1', ctypes.c_uint32, 3),
               ('field', ctypes.c_uint32, 12),
               ('action_type', ctypes.c_uint32, 4),
              ]

class _data0_union(ctypes.Union):
    _fields_ = [('data0', ctypes.c_uint32),
               ('data0_struct', _data0),
              ]

class _data1(ctypes.Structure):
    _fields_ = [('rsvd2', ctypes.c_uint32, 8),
               ('dst_offset', ctypes.c_uint32, 5),
               ('rsvd3', ctypes.c_uint32, 3),
               ('dst_field', ctypes.c_uint32, 12),
               ('rsvd4', ctypes.c_uint32, 4),
              ]

class _data1_union(ctypes.Union):
    _fields_ = [('data1', ctypes.c_uint32),
               ('data', ctypes.c_ubyte * 4),
               ('data1_struct', _data1),
              ]

class mlx5_modification_cmd(ctypes.Structure):
    _fields_ = [('data0_u', _data0_union),
               ('data1_u', _data1_union),
               ]

def _srd(cur_dict, key):
    # Safe Read from Dict (SRD)
    if (key in cur_dict.keys()):
        return str(cur_dict[key])
    else:
        return "None"


class dr_dump_ctx(object):
    domain = None
    table = None
    matcher = None
    rule = None
    line = []
    invalid_rule = []
    counter = {}
    encap_decap = {}
    modify_hdr = {}


# Base class for all SW steering object that will be read from a CSV dump file.
# Abstract class only (don't create instance).
class dr_obj(object):
    def __init__(self):
        self.data = {}

    def get(self, field_name):
        return self.data[field_name]

    def set(self, field_name, value):
        self.data[field_name] = value

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(dr_print_color.RESET, self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(dr_print_color.RESET, self.dump_str())


def inc_indent():
    global g_indent
    g_indent += 1


def dec_indent():
    global g_indent
    g_indent -= 1


def get_indet():
    return g_indent


def get_indent_str():
    global g_indent
    return TAB * g_indent


def set_colored_prints():
    global COLORED_PRINTS
    COLORED_PRINTS = True


class dr_print_color():
    color = {
        'darkwhite': "\033[0;37m",
        'darkyellow': "\033[0;33m",
        'darkgreen': "\033[1;32m",
        'darkblue': "\033[1;34m",
        'darkcyan': "\033[1;36m",
        'darkred': "\033[2;31m",
        'darkmagenta': "\033[0;35m",
        'off': "\033[0;0m"
    }

    DOMAIN = color["darkwhite"]
    TABLE = color["darkyellow"]
    MATCHER = color["darkblue"]
    MATCHER_MASK = color["darkblue"]
    RULE = color["darkgreen"]
    RULE_MATCH = color["darkgreen"]
    RULE_ACTIONS = color["darkgreen"]
    ERROR = color["darkred"]
    RESET = color["off"]


def print_dr(color, *args):
    global g_indent
    tab = TAB * g_indent
    str_ = tab + " ".join(map(str, args))

    if COLORED_PRINTS == True:
        sys.stdout.write(color)

    sys.stdout.write(str_)
    if COLORED_PRINTS == True:
        sys.stdout.write(dr_print_color.RESET)


def dict_join_str(in_dict):
    attrs = []
    for k, v in in_dict.items():
        attrs.append(str(k) + ": " + str(v))

    return ', '.join(attrs)


def conv_ip_version(version):
    if eval(version) == 1:
        return "0x4"
    elif eval(version) == 2:
        return "0x6"
    return "0x0"


def _val(field_str):
    nibbels = str(int(len(field_str) / 4))
    fmt = "0x{:0" + nibbels + "x}"
    return fmt.format(int(field_str, 2))


def add_inner_to_key(in_dict):
    for k, v in list(in_dict.items()):
        in_dict["inner_" + k] = v
        del in_dict[k]


def hex_2_bin(hex_str):
    # To save the first zeroes from being compressed by 'bin'
    hex_str = 'f' + hex_str
    # convert to binary and remove "0b1111"
    bin_str = bin(int(hex_str, 16))[6:]
    return bin_str

def mlx5_ifc_encap_decap(bin_str):
    ETH_HDR_LEN = 28
    VLAN_HDR_LEN = 8
    IPV4_HDR_LEN = 40
    IPV6_HDR_LEN = 80
    UDP_HDR_LEN = 16
    VXLAN_HDR_LEN = 16
    length = 0
    ret = {}
    if not bin_str:
        return

    _len = len(bin_str)
    if _len >= 108:
        #mac + vlan + ip
        has_vlan = True
    else:
        #mac + ip
        has_vlan = False

    ret["dmac"] = pretty_mac('0x'+bin_str[0: 12])
    ret["smac"] = pretty_mac('0x'+bin_str[12: 24])
    if has_vlan:
        ret["vid"] = int(bin_str[28: 32], 16) & 0xfff
        ret["ethtype"] = (bin_str[32: 36])  # 0x0800; ipv4, 0x86DD, ipv6
    else:
        ret["ethtype"] = (bin_str[24: 28])  # 0x0800; ipv4, 0x86DD, ipv6

    if has_vlan:
        length += (ETH_HDR_LEN + VLAN_HDR_LEN)
        off = 0
    else:
        length += ETH_HDR_LEN
        off = VLAN_HDR_LEN

    if ret["ethtype"] == '0800':
        ret["ip_type"] = int (bin_str[length + IPV4_HDR_LEN - 22 : length + IPV4_HDR_LEN - 20], 16)  # udp/ip
        ret["src_ip"] = pretty_ip(bin_str[length + IPV4_HDR_LEN - 16 : length + IPV4_HDR_LEN - 8])
        ret["dst_ip"] = pretty_ip(bin_str[length + IPV4_HDR_LEN - 8  : length + IPV4_HDR_LEN])
        length += IPV4_HDR_LEN
    else :
        ret["ip_type"] = (bin_str[length + IPV6_HDR_LEN - 68 + off: length + IPV6_HDR_LEN - 66 + off])  # udp/ip
        ret["src_ip"] = pretty_ip('0x' + bin_str[length + IPV6_HDR_LEN - 64 : length + IPV6_HDR_LEN - 32])
        ret["dst_ip"] = pretty_ip('0x' + bin_str[length + IPV6_HDR_LEN - 32 : length + IPV6_HDR_LEN])
        length += IPV6_HDR_LEN

    ret["udp_port"] = int(bin_str[length + UDP_HDR_LEN - 12 : length + UDP_HDR_LEN - 8], 16)
    length += UDP_HDR_LEN
    ret["flag"] = (bin_str[length + VXLAN_HDR_LEN - 16 : length + VXLAN_HDR_LEN - 8])
    ret["vni"] = int(bin_str[length + VXLAN_HDR_LEN - 8 : length + VXLAN_HDR_LEN-2], 16)
    if has_vlan:
        str = "vxlan tnl_push(dmac=%s, smac=%s, vid=%s, sip=%s, dip=%s, port=%s, vni=%s)" % \
                           (ret["dmac"], ret["smac"], ret["vid"], ret["src_ip"], ret["dst_ip"],
                           ret["udp_port"], ret["vni"])
    else:
        str = "vxlan tnl_push(dmac=%s, smac=%s, vlan null, sip=%s, dip=%s, port=%s, vni=%s)" % \
                           (ret["dmac"], ret["smac"], ret["src_ip"], ret["dst_ip"],
                           ret["udp_port"], ret["vni"])
    return str

def int_repl(match):
   return str(int(match.group(), 16)) + "."

def remove_prefix_zero(match):
   return str(match.group()).lstrip('0') + ":"

def mlx5_ifc_modify_hdr(num_str, bin_str):
   pattern = re.compile('.{2}')
   hdr_str = ''
   for i in range(int(num_str)):
       cmd = mlx5_modification_cmd()
       cmd.data0_u.data0 = int(bin_str[i*16:i*16+8], 16)
       cmd.data1_u.data1 = int(bin_str[i*16+8:i*16+16], 16)
       if cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_SMAC_47_16.value:
           hdr_str += ',smac=' + ':'.join(pattern.findall(bin_str[i*16+8:i*16+16])) + ":"
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_SMAC_15_0.value:
           hdr_str += ':'.join(pattern.findall(bin_str[i*16+12:i*16+16]))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_DMAC_47_16.value:
           hdr_str += ',dmac=' + ':'.join(pattern.findall(bin_str[i*16+8:i*16+16])) + ":"
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_DMAC_15_0.value:
           hdr_str += ':'.join(pattern.findall(bin_str[i*16+12:i*16+16]))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_SIPV4.value:
           hdr_str += ',sip4=' + pattern.sub(int_repl, bin_str[i*16+8:i*16+16]).rstrip('.')
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_DIPV4.value:
           hdr_str += ',dip4=' + pattern.sub(int_repl, bin_str[i*16+8:i*16+16]).rstrip('.')
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_SIPV6_127_96.value:
           pattern = re.compile('.{4}')
           hdr_str = ',sip6=' + pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_SIPV6_95_64.value:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_SIPV6_63_32.value:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_SIPV6_31_0.value:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16]).rstrip(":")
           hdr_str = (re.sub('(::+)', '::', hdr_str))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_DIPV6_127_96.value:
           pattern = re.compile('.{4}')
           hdr_str += ',dip6=' + pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_DIPV6_95_64.value:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_DIPV6_63_32.value:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_DIPV6_31_0.value:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16]).rstrip(":")
           hdr_str = (re.sub('(::+)', '::', hdr_str))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_TCP_SPORT.value:
           hdr_str = ',tcp_sport=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_TCP_DPORT.value:
           hdr_str += ',tcp_dport=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_IP_DSCP.value:
           hdr_str = ',ip_dscp=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_ETHERTYPE.value:
           #Fix ME. Contents in actions->conf
           hdr_str = ',modify_field'
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_IPV4_TTL.value:
           if cmd.data0_u.data0_struct.action_type == 1:
               hdr_str = ',ip4_ttl=' + str(int(bin_str[i*16+8:i*16+16], 16))
           elif cmd.data0_u.data0_struct.action_type == 2:
               #Add -1
               hdr_str = ',dec_ip4_ttl'
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_IPV6_HOPLIMIT.value:
           if cmd.data0_u.data0_struct.action_type == 1:
               hdr_str = ',ip6_hop=' + str(int(bin_str[i*16+8:i*16+16], 16))
           elif cmd.data0_u.data0_struct.action_type == 2:
               #Add -1
               hdr_str = ',dec_ip6_hop'
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_FIRST_VID.value:
           hdr_str = ',vid=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_UDP_SPORT.value:
           hdr_str = ',udp_sport=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_UDP_DPORT.value:
           hdr_str = ',udp_dport=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_TCP_ACK_NUM.value:
           if int(bin_str[i*16+8:i*16+9], 16) > 7:
               hdr_str = ',dec_tcp_ack=' + str(pow(2, 32) - int(bin_str[i*16+8:i*16+16], 16))
           else:
               hdr_str = ',add_tcp_ack=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_OUT_TCP_SEQ_NUM.value:
           if int(bin_str[i*16+8:i*16+9], 16) > 7:
               hdr_str = ',dec_tcp_seq=' + str(pow(2, 32) - int(bin_str[i*16+8:i*16+16], 16))
           else:
               hdr_str = ',add_tcp_seq=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.action_type == 3:
           #COPY MREG
           hdr_str = ',cp_reg'
           if cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_DATA_REG_A.value:
               hdr_str += '_a'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_DATA_REG_B.value:
               hdr_str += '_b'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_0.value:
               hdr_str += '_c0'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_1.value:
               hdr_str += '_c1'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_2.value:
               hdr_str += '_c2'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_3.value:
               hdr_str += '_c3'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_4.value:
               hdr_str += '_c4'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_5.value:
               hdr_str += '_c5'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_6.value:
               hdr_str += '_c6'
           elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_7.value:
               hdr_str += '_c7'
           if cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_DATA_REG_A.value:
               hdr_str += '_to_reg_a'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_DATA_REG_B.value:
               hdr_str = '_to_reg_b'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_0.value:
               hdr_str = '_to_reg_c0'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_1.value:
               hdr_str = '_to_reg_c1'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_2.value:
               hdr_str = '_to_reg_c2'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_3.value:
               hdr_str = '_to_reg_c3'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_4.value:
               hdr_str = '_to_reg_c4'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_5.value:
               hdr_str = '_to_reg_c5'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_6.value:
               hdr_str = '_to_reg_c6'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_7.value:
               hdr_str = '_to_reg_c7'
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_DATA_REG_A.value:
           hdr_str = ',set_reg_a=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_DATA_REG_B.value:
           hdr_str = ',set_reg_b=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_0.value:
           hdr_str = ',set_reg_c0=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_1.value:
           hdr_str = ',set_reg_c1=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_2.value:
           hdr_str = ',set_reg_c2=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_3.value:
           hdr_str = ',set_reg_c3=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_4.value:
           hdr_str = ',set_reg_c4=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_5.value:
           hdr_str = ',set_reg_c5=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_6.value:
           hdr_str = ',set_reg_c6=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MOD_FLD.MLX5_MODI_META_REG_C_7.value:
           hdr_str = ',set_reg_c7=' + str(int(bin_str[i*16+8:i*16+16], 16))
   return hdr_str

