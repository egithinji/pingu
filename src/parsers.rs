use crate::packets::arp::ArpRequest;
use crate::packets::icmp::IcmpRequest;
use crate::packets::ipv4::Ipv4;
use crate::senders::PacketType;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::sequence::tuple;
use nom::Err;
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
 * For example version and ihl from first byte,
 * or flags and fragment offset where 3 bits and then 13 bits taken from 2 bytes.
 * It only returns a tuple of two.
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
        let (_, second) = parse_bits_chunk::<'a, ()>(second_bits)
            .parse(tail)
            .unwrap();

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

    let icmp_checksum: u16 =
        (icmp_checksum[0] as u16).checked_shl(8).unwrap() + icmp_checksum[1] as u16;

    let identifier: u16 = (identifier[0] as u16).checked_shl(8).unwrap() + identifier[1] as u16;

    let sequence_number =
        (sequence_number[0] as u16).checked_shl(8).unwrap() + sequence_number[1] as u16;

    let data: [u8; 48] = data.try_into().unwrap();

    Ok((
        left_over,
        IcmpRequest {
            icmp_type: icmp_type[0],
            code: code[0],
            icmp_checksum,
            identifier,
            sequence_number,
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

    let htype: u16 = (htype[0] as u16).checked_shl(8).unwrap() + htype[1] as u16;

    let ptype: u16 = (ptype[0] as u16).checked_shl(8).unwrap() + ptype[1] as u16;

    let oper: u16 = (oper[0] as u16).checked_shl(8).unwrap() + oper[1] as u16;

    Ok((
        left_over,
        ArpRequest {
            htype,
            ptype,
            hlen: hlen[0],
            plen: plen[0],
            oper,
            sha: sha.try_into().unwrap(),
            spa: spa.try_into().unwrap(),
            tha: tha.try_into().unwrap(),
            tpa: tpa.try_into().unwrap(),
            raw_bytes: Vec::new(),
        },
    ))
}

pub fn parse_ipv4(bytes: &[u8]) -> IResult<&[u8], Ipv4> {
    let (_, start_of_data) = parse_adhoc_bits::<()>(4,4,1).parse(bytes).unwrap();
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

    let total_length: u16 =
        (total_length[0] as u16).checked_shl(8).unwrap() + total_length[1] as u16;

    let identification: u16 =
        (identification[0] as u16).checked_shl(8).unwrap() + identification[1] as u16;

    let header_checksum: u16 =
        (header_checksum[0] as u16).checked_shl(8).unwrap() + header_checksum[1] as u16;

    Ok((
        left_over,
        Ipv4 {
            version: version,
            ihl: ihl,
            type_of_service: type_of_service[0],
            total_length,
            identification,
            flags: flags as u8,
            fragment_offset,
            ttl: ttl[0],
            protocol: protocol[0],
            header_checksum,
            source_address: source_address.try_into().unwrap(),
            dest_address: dest_address.try_into().unwrap(),
            payload: data.to_vec(),
            raw_ip_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
            packet_type: PacketType::IcmpRequest,
        },
    ))
}

#[cfg(test)]
mod tests {

    use super::*;
    use nom::bits::complete::take;
    use nom::error::ParseError;

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

        let bits = 0b00110101;

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
}
