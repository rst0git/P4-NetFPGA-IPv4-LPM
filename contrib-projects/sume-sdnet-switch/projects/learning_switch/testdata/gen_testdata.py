#!/usr/bin/env python

from collections import OrderedDict
import sys
import os

from scapy.all import *

from nf_sim_tools import *
from sss_sume_metadata import *


tuple_in_file = "Tuple_in.txt"
tuple_expect_file = "Tuple_expect.txt"


def get_bin_val(field_name, value, field_len_dic):
    """
    Return a binary string with length = field_len_dic[field_name]
    """
    format_string = "{0:0%db}" % field_len_dic[field_name]
    return format_string.format(value)

def bin_to_hex(bin_string):
    """
    Given a binary string, return the hex version
    """
    hex_string = ''
    assert(len(bin_string) % 4 == 0)
    for i in range(0, len(bin_string), 4):
        hex_string += "{0:1x}".format(int(bin_string[i:i+4], 2))
    return hex_string

def write_tuples():
    """
    Write the next line of the Tuple_in.txt and Tuple_expect.txt
    """
    with open(tuple_in_file, "a") as f:
        tup_bin_string = ''
        for field_name, value in sume_tuple_in.iteritems():
            bin_val = get_bin_val(field_name, value, sume_field_len)
            tup_bin_string += bin_val
        f.write(bin_to_hex(tup_bin_string) + '\n')

    with open(tuple_expect_file, "a") as f:
        tup_bin_string = ''
        for field_name, value in dig_tuple_expect.iteritems():
            bin_val = get_bin_val(field_name, value, dig_field_len)
            tup_bin_string += bin_val
        f.write(bin_to_hex(tup_bin_string) + ' ')

        tup_bin_string = ''
        for field_name, value in sume_tuple_expect.iteritems():
            bin_val = get_bin_val(field_name, value, sume_field_len)
            tup_bin_string += bin_val
        f.write(bin_to_hex(tup_bin_string) + '\n')


class Digest_data(Packet):
    name = "Digest_data"
    fields_desc = [
        ByteField("src_port", 0),
        LELongField("eth_src_addr", 0),
        LELongField("unused1", 0),
        LELongField("unused2", 0),
        LEIntField("unused3", 0),
        X3BytesField("unused4", 0)
    ]

    def mysummary(self):
        return self.sprintf("src_port=%op1% eth_src_addr=%eth_src_addr% unused=%unused%")

def write_pcap_files():
    wrpcap("src.pcap", pktsApplied)
    wrpcap("dst.pcap", pktsExpected)

    for i in nf_applied.keys():
        if len(nf_applied[i]) > 0:
            wrpcap('nf{0}_applied.pcap'.format(i), nf_applied[i])

    for i in nf_expected.keys():
        if len(nf_expected[i]) > 0:
            wrpcap('nf{0}_expected.pcap'.format(i), nf_expected[i])

    for i in nf_applied.keys():
        print("nf{0}_applied times: ".format(i), [p.time for p in nf_applied[i]])


dig_field_len = OrderedDict()
dig_field_len['unused'] = 184
dig_field_len['eth_src_addr'] = 64
dig_field_len['src_port'] = 8

dig_tuple_expect = OrderedDict()
dig_tuple_expect['unused'] = 0
dig_tuple_expect['eth_src_addr'] = 0
dig_tuple_expect['src_port'] = 0

pktsApplied = []
pktsExpected = []

nf_applied = OrderedDict()
nf_applied[0] = []
nf_applied[1] = []
nf_applied[2] = []
nf_applied[3] = []

nf_expected = OrderedDict()
nf_expected[0] = []
nf_expected[1] = []
nf_expected[2] = []
nf_expected[3] = []

bind_layers(Digest_data, Raw)

with open(tuple_in_file, "w") as f:
    f.write("")

with open(tuple_expect_file, "w") as f:
    f.write("")

pkt = Ether(src="08:11:11:11:11:08", dst="08:22:22:22:22:08") / IP(src="192.168.10.1", dst="192.168.10.2") / TCP()
pkt = pad_pkt(pkt, 64)
pkt.time = 0

pktsApplied.append(pkt)
pktsExpected.append(pkt)
nf_applied[0].append(pkt)
nf_expected[1].append(pkt)

sume_tuple_in['src_port'] = 0b00000001
sume_tuple_expect['src_port'] = 0b00000001
sume_tuple_expect['dst_port'] = 0b00000100
sume_tuple_expect['send_dig_to_cpu'] = 0
dig_tuple_expect['src_port'] = 0
dig_tuple_expect['eth_src_addr'] = 0

write_tuples()

pkt = Ether(src="08:33:33:33:33:08", dst="08:44:44:44:44:08") / IP(src="192.168.20.3", dst="192.168.20.4") / TCP()
pkt = pad_pkt(pkt, 64)
pkt.time = 1

pktsApplied.append(pkt)
pktsExpected.append(pkt)
nf_applied[2].append(pkt)
nf_expected[3].append(pkt)

sume_tuple_in['src_port'] = 0b00000100
sume_tuple_expect['src_port'] = 0b00000100
sume_tuple_expect['dst_port'] = 0b01000000
sume_tuple_expect['send_dig_to_cpu'] = 0
dig_tuple_expect['src_port'] = 0
dig_tuple_expect['eth_src_addr'] = 0

write_tuples()

write_pcap_files()
