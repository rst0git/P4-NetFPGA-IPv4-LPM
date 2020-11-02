#include <core.p4>
#include <sume_switch.p4>

typedef bit<48> EthernetAddress;
const bit<16> ETHERTYPE_IP4  = 0x0800;

// standard Ethernet header
header Ethernet_h {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

struct Parsed_packet {
	Ethernet_h	ethernet;
	ipv4_t		ipv4;
}

struct digest_data_t {
    bit<184> unused;
    bit<64> eth_src_addr;  // 64 bits so we can use the LELongField type for scapy
    port_t src_port;
}

struct user_metadata_t {
    bit<8>  unused;
}

@Xilinx_MaxPacketRegion(16384)
parser TopParser(packet_in packet,
                 out Parsed_packet hdr,
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) {
    state start {
        user_metadata.unused = 0;
        digest_data.src_port = 0;
        digest_data.eth_src_addr = 0;
        digest_data.unused = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IP4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition  accept;
    }
}

control TopPipe(inout Parsed_packet headers,
                inout user_metadata_t user_metadata,
                inout digest_data_t digest_data,
                inout sume_metadata_t sume_metadata)
{
    action set_dst_port(port_t port) {
        sume_metadata.dst_port = port;
    }

    table forward {
        key = {
            headers.ipv4.dst_addr: lpm;
        }
        actions = {
            set_dst_port;
        }
        size = 63;
    }

    apply {
        sume_metadata.dst_port = 1;
        forward.apply();
    }
}

// Deparser Implementation
@Xilinx_MaxPacketRegion(16384)
control TopDeparser(packet_out packet,
                    in Parsed_packet hdr,
                    in user_metadata_t user_metadata,
                    inout digest_data_t digest_data,
                    inout sume_metadata_t sume_metadata) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}


// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;

