use crate::packets::ethernet::EthernetFrame;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;

struct EthDestMac<'a>(&'a [u8]);
struct EthSourceMac<'a>(&'a [u8]);
struct EthEtherType<'a>(&'a [u8]);
struct EthPayload<'a>(&'a [u8]);

fn parse_eth_dest_mac<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], EthDestMac<'a>, E> {
    move |input: &'a [u8]| match take(6usize)(input) {
        Ok((remainder, bytes)) => Ok((remainder, EthDestMac(bytes))),
        Err(e) => Err(e),
    }
}

fn parse_eth_src_mac<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], EthSourceMac<'a>, E> {
    move |input: &'a [u8]| match take(6usize)(input) {
        Ok((remainder, bytes)) => Ok((remainder, EthSourceMac(bytes))),
        Err(e) => Err(e),
    }
}

fn parse_eth_eth_type<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], EthEtherType<'a>, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => Ok((remainder, EthEtherType(bytes))),
        Err(e) => Err(e),
    }
}

fn parse_eth_payload<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], EthPayload<'a>, E> {
    move |input: &'a [u8]| match take(input.len())(input) {
        Ok((remainder, bytes)) => Ok((remainder, EthPayload(bytes))),
        Err(e) => Err(e),
    }
}

pub fn parse_ethernet(bytes: &[u8]) -> IResult<&[u8], EthernetFrame> {
    let mut operation = tuple((
        parse_eth_dest_mac(),
        parse_eth_src_mac(),
        parse_eth_eth_type(),
        parse_eth_payload(),
    ));

    let (left_over, (dest_mac, source_mac, eth_type, payload)) = operation.parse(bytes)?;

    let e = EthernetFrame::new(eth_type.0, payload.0, dest_mac.0, source_mac.0);

    Ok((left_over, e))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utilities::{get_wireshark_bytes, get_local_mac_ip};

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
}
