use crate::packets::icmp::IcmpRequest;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::number::complete::{be_u16, be_u8};
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;

type IcmpType = u8;
type IcmpCode = u8;
type IcmpChecksum = u16;
type IcmpIdentifier = u16;
type IcmpSeqNumber = u16;
type IcmpData = Vec<u8>;

fn parse_icmp_type<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpType, E> {
    move |input: &'a [u8]| match be_u8(input) {
        Ok((remainder, icmp_type)) => Ok((remainder, icmp_type)),
        Err(e) => Err(e),
    }
}

fn parse_icmp_code<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpCode, E> {
    move |input: &'a [u8]| match be_u8(input) {
        Ok((remainder, icmp_code)) => Ok((remainder, icmp_code)),
        Err(e) => Err(e),
    }
}

fn parse_icmp_checksum<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpChecksum, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, icmp_checksum)) => Ok((remainder, icmp_checksum)),
        Err(e) => Err(e),
    }
}

fn parse_icmp_identifier<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpIdentifier, E>
{
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, icmp_identifier)) => Ok((remainder, icmp_identifier)),
        Err(e) => Err(e),
    }
}

fn parse_icmp_seq_number<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpSeqNumber, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, icmp_seq_number)) => Ok((remainder, icmp_seq_number)),
        Err(e) => Err(e),
    }
}

fn parse_icmp_data<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpData, E> {
    move |input: &'a [u8]| match take(input.len() as usize)(input) {
        Ok((remainder, icmp_data)) => Ok((remainder, icmp_data.to_vec())),
        Err(e) => Err(e),
    }
}

pub fn parse_icmp(bytes: &[u8]) -> IResult<&[u8], IcmpRequest> {
    let mut operation = tuple((
        parse_icmp_type(),
        parse_icmp_code(),
        parse_icmp_checksum(),
        parse_icmp_identifier(),
        parse_icmp_seq_number(),
        parse_icmp_data(),
    ));

    let (left_over, (icmp_type, code, icmp_checksum, identifier, sequence_number, data)) =
        operation.parse(bytes)?;

    let data: [u8; 48] = data.try_into().unwrap();

    Ok((
        left_over,
        IcmpRequest {
            icmp_type,
            code,
            icmp_checksum,
            identifier,
            sequence_number,
            data,
            raw_icmp_bytes: Vec::new(),
        },
    ))
}

#[cfg(test)]
mod tests {

    use super::*;

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
}
