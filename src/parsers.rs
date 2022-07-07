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

struct IcmpType(u8);
struct IcmpCode(u8);
struct IcmpChecksum(u16);
struct IcmpIdentifier(u16);
struct IcmpSeqNumber(u16);
struct IcmpData(Vec<u8>);

struct ArpHtype(u16); //hardware type
struct ArpPtype(u16); //arp protocol type
struct ArpHlen(u8); //hardware addr length
struct ArpPlen(u8); //protocol addr length
struct ArpOper(u16); //operation
struct ArpSha<'a>(&'a [u8]); //sender hardware address
struct ArpSpa<'a>(&'a [u8]); //sender protocol address
struct ArpTha<'a>(&'a [u8]); //target hardware address
struct ArpTpa<'a>(&'a [u8]); //target protocol address

struct Ipv4Version(u16);
struct Ipv4Ihl(u16);
struct Ipv4Tos(u8);
struct Ipv4TotalLength(u16);
struct Ipv4Identification(u16);
struct Ipv4Flags(u8);
struct Ipv4FragmentOffset(u16);
struct Ipv4Ttl(u8);
struct Ipv4Protocol(u8);
struct Ipv4HeaderChecksum(u16);
struct Ipv4SourceAddress([u8; 4]);
struct Ipv4DestAddress([u8; 4]);
struct Ipv4Payload(Vec<u8>);

struct EthDestMac<'a>(&'a [u8]);
struct EthSourceMac<'a>(&'a [u8]);
struct EthEtherType<'a>(&'a [u8]);
struct EthPayload<'a>(&'a [u8]);

const TCPBYTESBEFOREOPTIONS: usize = 20;
struct TcpSrcPort(u16);
struct TcpDstPort(u16);
struct TcpSeqNum(u32);
struct TcpAckNum(u32);
struct TcpDataOffset(u8);
struct TcpReserved(u8);
struct TcpUrg(bool);
struct TcpAck(bool);
struct TcpPsh(bool);
struct TcpRst(bool);
struct TcpSyn(bool);
struct TcpFin(bool);
struct TcpWindow(u16);
struct TcpChecksum(u16);
struct TcpUrgentPointer(u16);
struct TcpOptions(Vec<u8>);
struct TcpData(Vec<u8>);

fn parse_icmp_type<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpType, E> {
    move |input: &'a [u8]| match take(1usize)(input) {
        Ok((remainder, byte)) => {
            let icmp_type = IcmpType(byte[0]);
            Ok((remainder, icmp_type))
        }
        Err(e) => Err(e),
    }
}

fn parse_icmp_code<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpCode, E> {
    move |input: &'a [u8]| match take(1usize)(input) {
        Ok((remainder, byte)) => {
            let icmp_code = IcmpCode(byte[0]);
            Ok((remainder, icmp_code))
        }
        Err(e) => Err(e),
    }
}

fn parse_icmp_checksum<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpChecksum, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let icmp_checksum = IcmpChecksum(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, icmp_checksum))
        }
        Err(e) => Err(e),
    }
}

fn parse_icmp_identifier<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpIdentifier, E>
{
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let icmp_identifier = IcmpIdentifier(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, icmp_identifier))
        }
        Err(e) => Err(e),
    }
}

fn parse_icmp_seq_number<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpSeqNumber, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let icmp_seq_number = IcmpSeqNumber(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, icmp_seq_number))
        }
        Err(e) => Err(e),
    }
}

fn parse_icmp_data<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], IcmpData, E> {
    move |input: &'a [u8]| match take(input.len() as usize)(input) {
        Ok((remainder, bytes)) => {
            let icmp_seq_number = IcmpData(bytes.to_vec());
            Ok((remainder, icmp_seq_number))
        }
        Err(e) => Err(e),
    }
}

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

fn parse_ipv4_version_and_ihl<'a, E>() -> impl Parser<&'a [u8], (Ipv4Version, Ipv4Ihl), E> {
    move |bytes| {
        let (remainder, byte) = parse_byte_chunk::<'a, ()>(1usize).parse(bytes).unwrap();
        let (tail, version) = parse_bits_chunk::<'a, ()>(4usize).parse((byte, 0)).unwrap();
        let (_, ihl) = parse_bits_chunk::<'a, ()>(4usize).parse(tail).unwrap();
        Ok((remainder, (Ipv4Version(version), Ipv4Ihl(ihl))))
    }
}

fn parse_ipv4_type_of_service<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], Ipv4Tos, E> {
    move |input: &'a [u8]| match take(1usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_tos = Ipv4Tos(u8::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, ipv4_tos))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_total_length<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4TotalLength, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_total_length = Ipv4TotalLength(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, ipv4_total_length))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_identification<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4Identification, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_identification =
                Ipv4Identification(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, ipv4_identification))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_flags_and_fragoffset<'a, E>(
) -> impl Parser<&'a [u8], (Ipv4Flags, Ipv4FragmentOffset), E> {
    move |bytes| {
        let (remainder, bytes) = parse_byte_chunk::<'a, ()>(2usize).parse(bytes).unwrap();
        let (tail, flags) = parse_bits_chunk::<'a, ()>(3usize)
            .parse((bytes, 0))
            .unwrap();
        let (_, fragment_offset) = parse_bits_chunk::<'a, ()>(13usize).parse(tail).unwrap();

        Ok((
            remainder,
            (Ipv4Flags(flags as u8), Ipv4FragmentOffset(fragment_offset)),
        ))
    }
}

fn parse_ipv4_ttl<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], Ipv4Ttl, E> {
    move |input: &'a [u8]| match take(1usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_ttl = Ipv4Ttl(u8::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, ipv4_ttl))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_protocol<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], Ipv4Protocol, E> {
    move |input: &'a [u8]| match take(1usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_protocol = Ipv4Protocol(u8::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, ipv4_protocol))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_header_checksum<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4HeaderChecksum, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_header_checksum =
                Ipv4HeaderChecksum(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, ipv4_header_checksum))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_source_address<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4SourceAddress, E> {
    move |input: &'a [u8]| match take(4usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_source_address = Ipv4SourceAddress(bytes.try_into().unwrap());
            Ok((remainder, ipv4_source_address))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_dest_address<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], Ipv4DestAddress, E> {
    move |input: &'a [u8]| match take(4usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_dest_address = Ipv4DestAddress(bytes.try_into().unwrap());
            Ok((remainder, ipv4_dest_address))
        }
        Err(e) => Err(e),
    }
}

fn parse_ipv4_payload<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], Ipv4Payload, E> {
    move |input: &'a [u8]| match take(input.len() as usize)(input) {
        Ok((remainder, bytes)) => {
            let ipv4_payload = Ipv4Payload(bytes.to_vec());
            Ok((remainder, ipv4_payload))
        }
        Err(e) => Err(e),
    }
}

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

fn parse_tcp_src_port<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpSrcPort, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let tcp_src_port = TcpSrcPort(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, tcp_src_port))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_dst_port<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpDstPort, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let tcp_dst_port = TcpDstPort(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, tcp_dst_port))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_seq_num<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpSeqNum, E> {
    move |input: &'a [u8]| match take(4usize)(input) {
        Ok((remainder, bytes)) => {
            let tcp_seq_num = TcpSeqNum(u32::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, tcp_seq_num))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_ack_num<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpAckNum, E> {
    move |input: &'a [u8]| match take(4usize)(input) {
        Ok((remainder, bytes)) => {
            let tcp_ack_num = TcpAckNum(u32::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, tcp_ack_num))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_dataoffset_and_reserved<'a, E>(
) -> impl Parser<&'a [u8], (TcpDataOffset, TcpReserved), E> {
    move |bytes| {
        let (remainder, bytes) = parse_byte_chunk::<'a, ()>(1usize).parse(bytes).unwrap();
        let (tail, data_offset) = parse_bits_chunk::<'a, ()>(4usize)
            .parse((bytes, 0))
            .unwrap();
        let (_, reserved) = parse_bits_chunk::<'a, ()>(4usize).parse(tail).unwrap();

        Ok((
            remainder,
            (
                TcpDataOffset(data_offset as u8),
                TcpReserved(reserved as u8),
            ),
        ))
    }
}

fn parse_tcp_flags<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], (TcpUrg, TcpAck, TcpPsh, TcpRst, TcpSyn, TcpFin), E> {
    move |input: &'a [u8]| match take(1usize)(input) {
        Ok((remainder, byte)) => {
            let (_, urg): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
                .parse((byte, 2)) //offset is 2 because first two bits are part of reserved bits
                .unwrap();
            let (_, ack): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
                .parse((byte, 3))
                .unwrap();
            let (_, psh): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
                .parse((byte, 4))
                .unwrap();
            let (_, rst): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
                .parse((byte, 5))
                .unwrap();
            let (_, syn): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
                .parse((byte, 6))
                .unwrap();
            let (_, fin): ((&[u8], usize), u8) = nom::bits::complete::take::<&[u8], u8, u8, ()>(1)
                .parse((byte, 7))
                .unwrap();

            Ok((
                remainder,
                (
                    TcpUrg(urg == 1),
                    TcpAck(ack == 1),
                    TcpPsh(psh == 1),
                    TcpRst(rst == 1),
                    TcpSyn(syn == 1),
                    TcpFin(fin == 1),
                ),
            ))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_window<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpWindow, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let tcp_window = TcpWindow(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, tcp_window))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_checksum<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpChecksum, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let tcp_checksum = TcpChecksum(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, tcp_checksum))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_urgent_pointer<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], TcpUrgentPointer, E> {
    move |input: &'a [u8]| match take(2usize)(input) {
        Ok((remainder, bytes)) => {
            let tcp_urgent_pointer =
                TcpUrgentPointer(u16::from_be_bytes(bytes.try_into().unwrap()));
            Ok((remainder, tcp_urgent_pointer))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_options<'a, E: ParseError<&'a [u8]>>(
    byte: u8,
) -> impl Parser<&'a [u8], TcpOptions, E> {
    //use data offset to determine start of data
    let byte = byte.to_be_bytes(); //the byte containing data offset value
    let (_, start_of_data): ((&[u8], usize), u8) =
        nom::bits::complete::take::<&[u8], u8, u8, ()>(4)
            .parse((&byte, 0))
            .unwrap();

    let start_of_data: usize = ((start_of_data as u16 * 32) / 8) as usize;

    move |input: &'a [u8]| match take(start_of_data - TCPBYTESBEFOREOPTIONS as usize)(input) {
        Ok((remainder, bytes)) => {
            let options = TcpOptions(bytes.to_vec());
            Ok((remainder, options))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_data<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpData, E> {
    move |input: &'a [u8]| match take(input.len() as usize)(input) {
        Ok((remainder, bytes)) => {
            let tcp_data = TcpData(bytes.to_vec());
            Ok((remainder, tcp_data))
        }
        Err(e) => Err(e),
    }
}

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
        parse_icmp_type(),
        parse_icmp_code(),
        parse_icmp_checksum(),
        parse_icmp_identifier(),
        parse_icmp_seq_number(),
        parse_icmp_data(),
    ));

    let (left_over, (icmp_type, code, icmp_checksum, identifier, sequence_number, data)) =
        operation.parse(bytes)?;

    let data: [u8; 48] = data.0.try_into().unwrap();

    Ok((
        left_over,
        IcmpRequest {
            icmp_type: icmp_type.0,
            code: code.0,
            icmp_checksum: icmp_checksum.0,
            identifier: identifier.0,
            sequence_number: sequence_number.0,
            data,
            raw_icmp_bytes: Vec::new(),
        },
    ))
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
            version: version.0,
            ihl: ihl.0,
            type_of_service: type_of_service.0,
            total_length: total_length.0,
            identification: identification.0,
            flags: flags.0,
            fragment_offset: fragment_offset.0,
            ttl: ttl.0,
            protocol: protocol.0,
            header_checksum: header_checksum.0,
            source_address: source_address.0,
            dest_address: dest_address.0,
            payload: data.0,
            raw_ip_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
            packet_type: PacketType::IcmpRequest,
        },
    ))
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

pub fn parse_tcp(bytes: &[u8]) -> IResult<&[u8], Tcp> {

    let mut operation = tuple((
        parse_tcp_src_port(),
        parse_tcp_dst_port(),
        parse_tcp_seq_num(),
        parse_tcp_ack_num(),
        parse_tcp_dataoffset_and_reserved(),
        parse_tcp_flags(),
        parse_tcp_window(),
        parse_tcp_checksum(),
        parse_tcp_urgent_pointer(),
        parse_tcp_options(bytes[12]),
        parse_tcp_data(),
    ));

    let (
        left_over,
        (
            src_port,
            dst_port,
            seq_number,
            ack_number,
            (data_offset, reserved),
            (urg, ack, psh, rst, syn, fin),
            window,
            checksum,
            urgent_pointer,
            options,
            data,
        ),
    ) = operation.parse(bytes)?;

    Ok((
        left_over,
        Tcp {
            src_port: src_port.0,
            dst_port: dst_port.0,
            seq_number: seq_number.0,
            ack_number: ack_number.0,
            data_offset: data_offset.0,
            reserved: reserved.0,
            urg: urg.0,
            ack: ack.0,
            psh: psh.0,
            rst: rst.0,
            syn: syn.0,
            fin: fin.0,
            window: window.0,
            checksum: checksum.0,
            urgent_pointer: urgent_pointer.0,
            options: options.0,
            data: data.0,
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
