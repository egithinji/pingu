use crate::packets::arp::ArpRequest;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::number::complete::{be_u16, be_u8};
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;

type ArpHtype = u16;
type ArpPtype = u16;
type ArpHlen = u8;
type ArpPlen = u8;
type ArpOper = u16;
type ArpSha<'a> = &'a [u8]; //sender hardware address
type ArpSpa<'a> = &'a [u8]; //sender protocol address
type ArpTha<'a> = &'a [u8]; //target hardware address
type ArpTpa<'a> = &'a [u8]; //target protocol address

fn parse_arp_htype<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpHtype, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, arp_htype)) => Ok((remainder, arp_htype)),
        Err(e) => Err(e),
    }
}

fn parse_arp_ptype<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpPtype, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, arp_ptype)) => Ok((remainder, arp_ptype)),
        Err(e) => Err(e),
    }
}

fn parse_arp_hlen<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpHlen, E> {
    move |input: &'a [u8]| match be_u8(input) {
        Ok((remainder, arp_hlen)) => Ok((remainder, arp_hlen)),
        Err(e) => Err(e),
    }
}

fn parse_arp_plen<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpPlen, E> {
    move |input: &'a [u8]| match be_u8(input) {
        Ok((remainder, arp_plen)) => Ok((remainder, arp_plen)),
        Err(e) => Err(e),
    }
}

fn parse_arp_oper<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpOper, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, arp_oper)) => Ok((remainder, arp_oper)),
        Err(e) => Err(e),
    }
}

fn parse_arp_sha<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpSha<'a>, E> {
    move |input: &'a [u8]| match take(6usize)(input) {
        Ok((remainder, arp_sha)) => Ok((remainder, arp_sha)),
        Err(e) => Err(e),
    }
}

fn parse_arp_spa<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpSpa<'a>, E> {
    move |input: &'a [u8]| match take(4usize)(input) {
        Ok((remainder, arp_spa)) => Ok((remainder, arp_spa)),
        Err(e) => Err(e),
    }
}

fn parse_arp_tha<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpTha<'a>, E> {
    move |input: &'a [u8]| match take(6usize)(input) {
        Ok((remainder, arp_tha)) => Ok((remainder, arp_tha)),
        Err(e) => Err(e),
    }
}

fn parse_arp_tpa<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpTpa<'a>, E> {
    move |input: &'a [u8]| match take(4usize)(input) {
        Ok((remainder, arp_tpa)) => Ok((remainder, arp_tpa)),
        Err(e) => Err(e),
    }
}

pub fn parse_arp(bytes: &[u8]) -> IResult<&[u8], ArpRequest> {
    let mut operation = tuple((
        parse_arp_htype(),
        parse_arp_ptype(),
        parse_arp_hlen(),
        parse_arp_plen(),
        parse_arp_oper(),
        parse_arp_sha(),
        parse_arp_spa(),
        parse_arp_tha(),
        parse_arp_tpa(),
    ));

    let (left_over, (htype, ptype, hlen, plen, oper, sha, spa, tha, tpa)) =
        operation.parse(bytes)?;

    Ok((
        left_over,
        ArpRequest {
            htype,
            ptype,
            hlen,
            plen,
            oper,
            sha,
            spa,
            tha,
            tpa,
            raw_bytes: Vec::new(),
        },
    ))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::parsers::arp_parser::parse_arp;
    use crate::utilities::{get_wireshark_bytes,get_local_mac_ip};

    #[test]
    pub fn test_arp_parse() {
        let test_bytes = &get_wireshark_bytes("test_arp_request_bytes.txt")[..];
        let (local_mac,_) = get_local_mac_ip();

        let expected = ArpRequest {
            htype: 1,
            ptype: 2048,
            hlen: 6,
            plen: 4,
            oper: 1,
            sha: &local_mac[..],
            spa: &[192, 168, 100, 16],
            tha: &[0, 0, 0, 0, 0, 0],
            tpa: &[192, 168, 100, 129],
            raw_bytes: Vec::new(),
        };

        let (_, arp_packet) = parse_arp(test_bytes).unwrap();
        assert_eq!(expected.htype, arp_packet.htype);
        assert_eq!(expected.ptype, arp_packet.ptype);
        assert_eq!(expected.hlen, arp_packet.hlen);
        assert_eq!(expected.plen, arp_packet.plen);
        assert_eq!(expected.oper, arp_packet.oper);
        assert_eq!(expected.sha, arp_packet.sha);
        assert_eq!(expected.spa, arp_packet.spa);
        assert_eq!(expected.tha, arp_packet.tha);
        assert_eq!(expected.tpa, arp_packet.tpa);
    }
}
