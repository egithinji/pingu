use crate::packets::arp::ArpRequest;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;

struct ArpHtype(u16);
struct ArpPtype(u16);
struct ArpHlen(u8);
struct ArpPlen(u8);
struct ArpOper(u16);
struct ArpSha<'a>(&'a [u8]); //sender hardware address
struct ArpSpa<'a>(&'a [u8]); //sender protocol address
struct ArpTha<'a>(&'a [u8]); //target hardware address
struct ArpTpa<'a>(&'a [u8]); //target protocol address

fn parse_arp_htype<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpHtype, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_htype = ArpHtype(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, arp_htype))
        }
        Err(e) => Err(e),
    }
}

fn parse_arp_ptype<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpPtype, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_ptype = ArpPtype(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, arp_ptype))
        }
        Err(e) => Err(e),
    }
}

fn parse_arp_hlen<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpHlen, E> {
    move |input: &'a [u8]| match take(1usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_hlen = ArpHlen(u8::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, arp_hlen))
        }
        Err(e) => Err(e),
    }
}

fn parse_arp_plen<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpPlen, E> {
    move |input: &'a [u8]| match take(1usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_plen = ArpPlen(u8::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, arp_plen))
        }
        Err(e) => Err(e),
    }
}

fn parse_arp_oper<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpOper, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_oper = ArpOper(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, arp_oper))
        }
        Err(e) => Err(e),
    }
}

fn parse_arp_sha<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpSha<'a>, E> {
    move |input: &'a [u8]| match take(6usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_sha = ArpSha(bytes);
            Ok((remainder, arp_sha))
        }
        Err(e) => Err(e),
    }
}

fn parse_arp_spa<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpSpa<'a>, E> {
    move |input: &'a [u8]| match take(6usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_sha = ArpSpa(bytes);
            Ok((remainder, arp_sha))
        }
        Err(e) => Err(e),
    }
}

fn parse_arp_tha<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpTha<'a>, E> {
    move |input: &'a [u8]| match take(6usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_tha = ArpTha(bytes);
            Ok((remainder, arp_tha))
        }
        Err(e) => Err(e),
    }
}

fn parse_arp_tpa<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], ArpTpa<'a>, E> {
    move |input: &'a [u8]| match take(6usize)(input) {
        Ok((remainder, bytes)) => {
            let arp_tpa = ArpTpa(bytes);
            Ok((remainder, arp_tpa))
        }
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
            htype: htype.0,
            ptype: ptype.0,
            hlen: hlen.0,
            plen: plen.0,
            oper: oper.0,
            sha: sha.0,
            spa: spa.0,
            tha: tha.0,
            tpa: tpa.0,
            raw_bytes: Vec::new(),
        },
    ))
}


#[cfg(test)]
mod tests {
    
    use super::*;



}
