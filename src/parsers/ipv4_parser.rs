use crate::packets::ipv4::Ipv4;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;
use nom::number::complete::{be_u16, be_u8};

type Ipv4Version = u16;
type Ipv4Ihl = u16;
type Ipv4Tos = u8;
type Ipv4TotalLength = u16;
type Ipv4Identification = u16;
type Ipv4Flags = u8;
type Ipv4FragmentOffset = u16;
type Ipv4Ttl = u8;
type Ipv4Protocol = u8;
type Ipv4HeaderChecksum = u16;
type Ipv4SourceAddress = [u8; 4];
type Ipv4DestAddress = [u8; 4];
type Ipv4Payload = Vec<u8>;

fn parse_ipv4_version_and_ihl<'a, E>() -> impl Parser<&'a [u8], (Ipv4Version, Ipv4Ihl), E> {
    move |bytes| {
        let (remainder, byte) = take::<usize, &'a [u8], ()>(1usize)(bytes).unwrap();
        let (tail, version) = nom::bits::complete::take::<&'a [u8], u8, usize, ()>(4usize)((byte,0)).unwrap();
        let (_, ihl) = nom::bits::complete::take::<&'a [u8], u16, usize, ()>(4usize)(tail).unwrap();
        Ok((remainder, (version as u16, ihl)))
    }
}

fn parse_ipv4_type_of_service<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], Ipv4Tos, E> {
    move |input: &'a [u8]| match be_u8(input) {
        Ok((remainder, ipv4_tos)) => Ok((remainder, ipv4_tos)),
        Err(e) => Err(e),
    }
}

fn parse_ipv4_total_length<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4TotalLength, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, ipv4_totallength)) => Ok((remainder, ipv4_totallength)),
        Err(e) => Err(e),
    }

}

fn parse_ipv4_identification<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4Identification, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, ipv4_identification)) => Ok((remainder, ipv4_identification)),
        Err(e) => Err(e),
    }
}

fn parse_ipv4_flags_and_fragoffset<'a, E>(
) -> impl Parser<&'a [u8], (Ipv4Flags, Ipv4FragmentOffset), E> {
    move |bytes| {
        let (remainder, bytes) = take::<usize, &'a [u8], ()>(2usize)(bytes).unwrap();
        
        let (tail, flags) = nom::bits::complete::take::<&'a [u8], u8, usize, ()>(3usize)((bytes,0)).unwrap();

        let (_, fragment_offset) = nom::bits::complete::take::<&'a [u8], u16, usize, ()>(13usize)(tail).unwrap();

        Ok((
            remainder,
            (flags as u8, fragment_offset),
        ))
    }
}

fn parse_ipv4_ttl<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], Ipv4Ttl, E> {
    move |input: &'a [u8]| match be_u8(input) {
        Ok((remainder, ipv4_ttl)) => Ok((remainder, ipv4_ttl)),
        Err(e) => Err(e),
    }
}

fn parse_ipv4_protocol<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], Ipv4Protocol, E> {

    move |input: &'a [u8]| match be_u8(input) {
        Ok((remainder, ipv4_protocol)) => Ok((remainder, ipv4_protocol)),
        Err(e) => Err(e),
    }

}

fn parse_ipv4_header_checksum<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4HeaderChecksum, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, ipv4_hchecksum)) => Ok((remainder, ipv4_hchecksum)),
        Err(e) => Err(e),
    }
}

fn parse_ipv4_source_address<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4SourceAddress, E> {
    move |input: &'a [u8]| match take(4usize)(input) {
        Ok((remainder, ipv4_source_address)) => {
            Ok((remainder, ipv4_source_address.try_into().unwrap()))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_dest_address<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4DestAddress, E> {
    move |input: &'a [u8]| match take(4usize)(input) {
        Ok((remainder, ipv4_dest_address)) => {
            Ok((remainder, ipv4_dest_address.try_into().unwrap()))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_payload<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], Ipv4Payload, E> {
    move |input: &'a [u8]| match take(input.len() as usize)(input) {
        Ok((remainder, ipv4_payload)) => {
            Ok((remainder, ipv4_payload.to_vec()))
        }
        Err(e) => Err(e),
    }
}

pub fn parse_ipv4(bytes: &[u8]) -> IResult<&[u8], Ipv4> {
    let mut operation = tuple((
        parse_ipv4_version_and_ihl(),
        parse_ipv4_type_of_service(),
        parse_ipv4_total_length(),
        parse_ipv4_identification(),
        parse_ipv4_flags_and_fragoffset(),
        parse_ipv4_ttl(),
        parse_ipv4_protocol(),
        parse_ipv4_header_checksum(),
        parse_ipv4_source_address(),
        parse_ipv4_dest_address(),
        parse_ipv4_payload(),
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
            type_of_service: type_of_service,
            total_length: total_length,
            identification: identification,
            flags: flags,
            fragment_offset: fragment_offset,
            ttl: ttl,
            protocol: protocol,
            header_checksum: header_checksum,
            source_address: source_address,
            dest_address: dest_address,
            payload: data,
            raw_ip_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
        },
    ))
}

#[cfg(test)]
mod tests {

    use super::*;

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
