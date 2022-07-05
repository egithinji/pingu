use crate::packets::arp::ArpRequest;
use crate::packets::ethernet::EthernetFrame;
use crate::packets::icmp::IcmpRequest;
use crate::packets::ipv4::Ipv4;
use crate::packets::tcp::Tcp;
use crate::senders::PacketType;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;

fn parse_byte_chunk<'a, E: ParseError<&'a [u8]>>(
    chunk_size: usize,
) -> impl Parser<&'a [u8], &'a [u8], E> {
    move |input: &'a [u8]| take(chunk_size)(input)
}

fn parse_bits_chunk<'a, E: ParseError<(&'a [u8], usize)>>(
    chunk_size: usize,
) -> impl Parser<(&'a [u8], usize), u16, E> {
    move |(input, offset)| nom::bits::complete::take(chunk_size)((input, offset))
}

/*For use when I need to get specific bits from a byte or bytes.
 * For example when pasing an ipv4 packet, the version and ihl are
 * contained in the first four and second four bits of the first byte
 * respectively. This parser is only capable of returning a tuple of two.
 * */
fn parse_adhoc_bits<'a, E>(
    first_bits: usize,
    second_bits: usize,
    num_bytes: usize,
) -> impl Parser<&'a [u8], (u16, u16), E> {
    move |bytes| {
        let (remainder, chunk) = parse_byte_chunk::<'a, ()>(num_bytes).parse(bytes).unwrap();
        let (tail, first) = parse_bits_chunk::<'a, ()>(first_bits)
            .parse((chunk, 0))
            .unwrap();
        let (_, second) = parse_bits_chunk::<'a, ()>(second_bits).parse(tail).unwrap();

        Ok((remainder, (first, second)))
    }
}

pub fn parse_icmp(bytes: &[u8]) -> IResult<&[u8], IcmpRequest> {
    let mut operation = tuple((
        parse_byte_chunk(1),
        parse_byte_chunk(1),
        parse_byte_chunk(2),
        parse_byte_chunk(2),
        parse_byte_chunk(2),
        parse_byte_chunk(48),
    ));

    let (left_over, (icmp_type, code, icmp_checksum, identifier, sequence_number, data)) =
        operation.parse(bytes)?;

    let data: [u8; 48] = data.try_into().unwrap();

    Ok((
        left_over,
        IcmpRequest {
            icmp_type: icmp_type[0],
            code: code[0],
            icmp_checksum: u16::from_be_bytes(icmp_checksum.try_into().unwrap()),
            identifier: u16::from_be_bytes(identifier.try_into().unwrap()),
            sequence_number: u16::from_be_bytes(sequence_number.try_into().unwrap()),
            data,
            raw_icmp_bytes: Vec::new(),
        },
    ))
}

pub fn parse_arp(bytes: &[u8]) -> IResult<&[u8], ArpRequest> {
    let mut operation = tuple((
        parse_byte_chunk(2), //htype
        parse_byte_chunk(2), //ptype
        parse_byte_chunk(1), //hlen
        parse_byte_chunk(1), //plen
        parse_byte_chunk(2), //oper
        parse_byte_chunk(6), //sha
        parse_byte_chunk(4), //spa
        parse_byte_chunk(6), //tha
        parse_byte_chunk(4), //tpa
    ));

    let (left_over, (htype, ptype, hlen, plen, oper, sha, spa, tha, tpa)) =
        operation.parse(bytes)?;

    Ok((
        left_over,
        ArpRequest {
            htype: u16::from_be_bytes(htype.try_into().unwrap()),
            ptype: u16::from_be_bytes(ptype.try_into().unwrap()),
            hlen: hlen[0],
            plen: plen[0],
            oper: u16::from_be_bytes(oper.try_into().unwrap()),
            sha: sha.try_into().unwrap(),
            spa: spa.try_into().unwrap(),
            tha: tha.try_into().unwrap(),
            tpa: tpa.try_into().unwrap(),
            raw_bytes: Vec::new(),
        },
    ))
}

pub fn parse_ipv4(bytes: &[u8]) -> IResult<&[u8], Ipv4> {
    let (_, start_of_data) = parse_adhoc_bits::<()>(4, 4, 1).parse(bytes).unwrap();
    let start_of_data: usize = ((start_of_data.1 * 32) / 8) as usize;

    let mut operation = tuple((
        parse_adhoc_bits(4, 4, 1),                     //version and ihl
        parse_byte_chunk(1),                           //type_of_service
        parse_byte_chunk(2),                           //total_length
        parse_byte_chunk(2),                           //identification
        parse_adhoc_bits(3, 13, 2),                    //flags and frag offset
        parse_byte_chunk(1),                           //ttl
        parse_byte_chunk(1),                           //protocol
        parse_byte_chunk(2),                           //header checksum
        parse_byte_chunk(4),                           //source address
        parse_byte_chunk(4),                           //dest address
        parse_byte_chunk(bytes.len() - start_of_data), //data
    ));

    let (
        left_over,
        (
            (version, ihl),
            type_of_service,
            total_length,
            identification,
            (flags, fragment_offset),
            ttl,
            protocol,
            header_checksum,
            source_address,
            dest_address,
            data,
        ),
    ) = operation.parse(bytes)?;

    Ok((
        left_over,
        Ipv4 {
            version: version,
            ihl: ihl,
            type_of_service: type_of_service[0],
            total_length: u16::from_be_bytes(total_length.try_into().unwrap()),
            identification: u16::from_be_bytes(identification.try_into().unwrap()),
            flags: flags as u8,
            fragment_offset,
            ttl: ttl[0],
            protocol: protocol[0],
            header_checksum: u16::from_be_bytes(header_checksum.try_into().unwrap()),
            source_address: source_address.try_into().unwrap(),
            dest_address: dest_address.try_into().unwrap(),
            payload: data.to_vec(),
            raw_ip_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
            packet_type: PacketType::IcmpRequest,
        },
    ))
}

pub fn parse_ethernet(bytes: &[u8]) -> IResult<&[u8], EthernetFrame> {
    let mut operation = tuple((
        parse_byte_chunk(6),                //dest_mac
        parse_byte_chunk(6),                //source_mac
        parse_byte_chunk(2),                //eth_type
        parse_byte_chunk(bytes.len() - 14), //payload
    ));

    let (left_over, (dest_mac, source_mac, eth_type, payload)) = operation.parse(bytes)?;

    let e = EthernetFrame::new(eth_type, payload, dest_mac, source_mac);

    Ok((left_over, e))
}

pub fn parse_tcp(bytes: &[u8]) -> IResult<&[u8], Tcp> {
    let thirteenth_byte = &bytes[12].to_be_bytes(); //the byte containing data offset value
    let (_, start_of_data): ((&[u8], usize), u8) =
        nom::bits::complete::take::<&[u8], u8, u8, ()>(4)
            .parse((thirteenth_byte, 0))
            .unwrap();

    let start_of_data: u16 = start_of_data as u16;
    let start_of_data: usize = ((start_of_data * 32) / 8) as usize;

    let mut operation = tuple((
        parse_byte_chunk(2),       //src_port
        parse_byte_chunk(2),       //dst_port
        parse_byte_chunk(4),       //seq_number
        parse_byte_chunk(4),       //ack_number
        parse_adhoc_bits(4, 4, 1), //data offset
        parse_adhoc_bits(2, 6, 1), //flags (individual flags separated after operation
        parse_byte_chunk(2),       //window
        parse_byte_chunk(2),       //checksum
        parse_byte_chunk(2),       //urgent_pointer
        parse_byte_chunk(start_of_data - 20), //options
        parse_byte_chunk(bytes.len() - start_of_data), //data
    ));

    let (
        left_over,
        (
            src_port,
            dst_port,
            seq_number,
            ack_number,
            (data_offset, _),
            (_, flags),
            window,
            checksum,
            urgent_pointer,
            options,
            data,
        ),
    ) = operation.parse(bytes)?;

    let flags: [u8;1] = [flags as u8];

    let (_, urg): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
        .parse((&flags, 2))
        .unwrap();
    let (_, ack): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
        .parse((&flags, 3))
        .unwrap();
    let (_, psh): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
        .parse((&flags, 4))
        .unwrap();
    let (_, rst): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
        .parse((&flags, 5))
        .unwrap();
    let (_, syn): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
        .parse((&flags, 6))
        .unwrap();
    let (_, fyn): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
        .parse((&flags, 7))
        .unwrap();
    
    Ok((
        left_over,
        Tcp {
            src_port: u16::from_be_bytes(src_port.try_into().unwrap()),
            dst_port: u16::from_be_bytes(dst_port.try_into().unwrap()),
            seq_number: u32::from_be_bytes(seq_number.try_into().unwrap()),
            ack_number: u32::from_be_bytes(ack_number.try_into().unwrap()),
            data_offset: data_offset as u8,
            reserved: 0,
            urg: urg == 1u8,
            ack: ack == 1u8,
            psh: psh == 1u8,
            rst: rst == 1u8,
            syn: syn == 1u8,
            fin: fyn == 1u8,
            window: u16::from_be_bytes(window.try_into().unwrap()),
            checksum: u16::from_be_bytes(checksum.try_into().unwrap()),
            urgent_pointer: u16::from_be_bytes(urgent_pointer.try_into().unwrap()),
            options: options.to_vec(),
            data: data.to_vec(),
            raw_tcp_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
        },
    ))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utilities::{get_local_mac_ip, get_wireshark_bytes};

    #[test]
    pub fn test_bits_parse<'a>() {
        assert_eq!(
            parse_bits_chunk::<'a, ()>(4).parse(([0b11110000].as_ref(), 0)),
            Ok((([0b11110000].as_ref(), 4), 0b00001111))
        );

        assert_eq!(
            parse_bits_chunk::<'a, ()>(4).parse(([0b00001111].as_ref(), 0)),
            Ok((([0b00001111].as_ref(), 4), 0b00000000))
        );

        let (tail, first_four) = parse_bits_chunk::<'a, ()>(4)
            .parse(([0b00110101].as_ref(), 0))
            .unwrap();
        let (_, second_four) = parse_bits_chunk::<'a, ()>(4).parse(tail).unwrap();
        assert_eq!(first_four, 0b00000011);
        assert_eq!(second_four, 0b00000101);
    }

    #[test]
    pub fn test_icmp_parse() {
        //test_bytes are taken contents of icmp reply received from 8.8.8.8 after pinging from Linux.
        let test_bytes = &[
            0x00, 0x00, 0x1a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x2f, 0x0b, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ]
        .to_vec()[..];

        const DATA: [u8; 48] = [
            0x1b, 0x2f, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
            0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];

        let expected = IcmpRequest {
            icmp_type: 0,
            code: 0,
            icmp_checksum: 6910,
            identifier: 0,
            sequence_number: 0,
            data: DATA,
            raw_icmp_bytes: Vec::new(),
        };

        let (_, test_icmp_packet) = parse_icmp(test_bytes).unwrap();

        assert_eq!(test_icmp_packet.icmp_type, expected.icmp_type);
        assert_eq!(test_icmp_packet.code, expected.code);
        assert_eq!(test_icmp_packet.icmp_checksum, expected.icmp_checksum);
        assert_eq!(test_icmp_packet.identifier, expected.identifier);
        assert_eq!(test_icmp_packet.sequence_number, expected.sequence_number);
        assert_eq!(test_icmp_packet.data, expected.data);
    }

    #[test]
    pub fn test_ipv4_parse() {
        //test are taken contents of icmp reply received from 8.8.8.8 after pinging from Linux.
        let test_bytes = &[
            0x45, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x01, 0x4a, 0xe9, 0x08, 0x08,
            0x08, 0x08, 0xc0, 0xa8, 0x64, 0x10, 0x00, 0x00, 0x1a, 0xfe, 0x00, 0x00, 0x00, 0x00,
            0x1b, 0x2f, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
            0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ]
        .to_vec()[..];

        let expected = Ipv4 {
            version: 4,
            ihl: 5,
            type_of_service: 0,
            total_length: 76,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 59,
            protocol: 1,
            header_checksum: 19177,
            source_address: [8, 8, 8, 8],
            dest_address: [192, 168, 100, 16],
            payload: test_bytes[20..].to_vec(),
            raw_ip_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
            packet_type: PacketType::IcmpRequest,
        };

        let (_, test_ip_packet) = parse_ipv4(test_bytes).unwrap();
        assert_eq!(test_ip_packet.version, expected.version);
        assert_eq!(test_ip_packet.ihl, expected.ihl);
        assert_eq!(test_ip_packet.type_of_service, expected.type_of_service);
        assert_eq!(test_ip_packet.total_length, expected.total_length);
        assert_eq!(test_ip_packet.identification, expected.identification);
        assert_eq!(test_ip_packet.flags, expected.flags);
        assert_eq!(test_ip_packet.fragment_offset, expected.fragment_offset);
        assert_eq!(test_ip_packet.ttl, expected.ttl);
        assert_eq!(test_ip_packet.protocol, expected.protocol);
        assert_eq!(test_ip_packet.header_checksum, expected.header_checksum);
        assert_eq!(test_ip_packet.source_address, expected.source_address);
        assert_eq!(test_ip_packet.dest_address, expected.dest_address);
        assert_eq!(test_ip_packet.payload, expected.payload);
    }

    #[test]
    pub fn test_ethernet_parse() {
        //test_bytes are taken contents of icmp reply received from 8.8.8.8 after pinging from Linux.
        let test_bytes = &get_wireshark_bytes("test_ethernet_frame_reply.txt")[..];
        let (dest_mac, _) = get_local_mac_ip();
        let dest_mac: [u8; 6] = dest_mac.try_into().unwrap();
        let source_mac: [u8; 6] = get_wireshark_bytes("test_default_gateway_mac.txt")
            .try_into()
            .unwrap();
        let expected = EthernetFrame {
            dest_mac: &dest_mac,
            source_mac: &source_mac,
            ether_type: &[0x08, 0x00],
            payload: &vec![0; 84], //Not interested in contents of payload but the length should be correct
            fcs: [0, 0, 0, 0],     //Not interested in comparing fcs
            raw_bytes: vec![0; 98], //Just interested in the length
        };

        let (_, test_eth_frame) = parse_ethernet(test_bytes).unwrap();
        assert_eq!(test_eth_frame.dest_mac, expected.dest_mac);
        assert_eq!(test_eth_frame.source_mac, expected.source_mac);
        assert_eq!(test_eth_frame.ether_type, expected.ether_type);
        assert_eq!(test_eth_frame.payload.len(), expected.payload.len());
        assert_eq!(test_eth_frame.raw_bytes.len() - 4, test_bytes.len()); //-4 becase of fcs
    }

    #[test]
    pub fn test_tcp_parse() {
        //test bytes are initial syn request sent to www.example.com from linux
        let test_bytes = &[
            0xb5, 0x1c, 0x01, 0xbb, 0xd8, 0x0b, 0x2e, 0x77, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0xfa, 0xf0, 0x5a, 0xc2, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0xfd, 0x50, 0x50, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];

        let expected = Tcp {
            src_port: 46364,
            dst_port: 443,
            seq_number: 3624611447,
            ack_number: 0,
            data_offset: 10,
            reserved: 0,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: true,
            fin: false,
            window: 64240,
            checksum: 23234,
            urgent_pointer: 0,
            options: test_bytes[20..].to_vec(),
            data: Vec::new(),
            raw_tcp_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
        };

        let (_, test_tcp_packet) = parse_tcp(test_bytes).unwrap();
        assert_eq!(test_tcp_packet.src_port, expected.src_port);
        assert_eq!(test_tcp_packet.dst_port, expected.dst_port);
        assert_eq!(test_tcp_packet.seq_number, expected.seq_number);
        assert_eq!(test_tcp_packet.ack_number, expected.ack_number);
        assert_eq!(test_tcp_packet.data_offset, expected.data_offset);
        assert_eq!(test_tcp_packet.reserved, expected.reserved);
        assert_eq!(test_tcp_packet.urg, expected.urg);
        assert_eq!(test_tcp_packet.ack, expected.ack);
        assert_eq!(test_tcp_packet.psh, expected.psh);
        assert_eq!(test_tcp_packet.rst, expected.rst);
        assert_eq!(test_tcp_packet.syn, expected.syn);
        assert_eq!(test_tcp_packet.fin, expected.fin);
        assert_eq!(test_tcp_packet.window, expected.window);
        assert_eq!(test_tcp_packet.checksum, expected.checksum);
        assert_eq!(
            test_tcp_packet.urgent_pointer,
            test_tcp_packet.urgent_pointer
        );
        assert_eq!(test_tcp_packet.options, expected.options);
        assert_eq!(test_tcp_packet.data, expected.data);
    }
}
