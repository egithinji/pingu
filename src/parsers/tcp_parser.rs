use crate::packets::tcp::Tcp;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;
use nom::number::complete::{be_u16, be_u8, be_u32};

const TCPBYTESBEFOREOPTIONS: usize = 20;
type TcpSrcPort = u16;
type TcpDstPort = u16;
type TcpSeqNum = u32;
type TcpAckNum = u32;
type TcpDataOffset = u8;
type TcpReserved = u8;
type TcpUrg = bool;
type TcpAck = bool;
type TcpPsh = bool;
type TcpRst = bool;
type TcpSyn = bool;
type TcpFin = bool;
type TcpWindow = u16;
type TcpChecksum = u16;
type TcpUrgentPointer = u16;
type TcpOptions = Vec<u8>;
type TcpData = Vec<u8>;

fn parse_tcp_src_port<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpSrcPort, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, tcpsrcport)) => Ok((remainder, tcpsrcport)),
        Err(e) => Err(e),
    }
}

fn parse_tcp_dst_port<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpDstPort, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, tcpdstport)) => Ok((remainder, tcpdstport)),
        Err(e) => Err(e),
    }
}

fn parse_tcp_seq_num<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpSeqNum, E> {
    move |input: &'a [u8]| match be_u32(input) {
        Ok((remainder, tcpseqnum)) => Ok((remainder, tcpseqnum)),
        Err(e) => Err(e),
    }
}

fn parse_tcp_ack_num<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpAckNum, E> {
    move |input: &'a [u8]| match be_u32(input) {
        Ok((remainder, tcpacknum)) => Ok((remainder, tcpacknum)),
        Err(e) => Err(e),
    }
}

fn parse_tcp_dataoffset_and_reserved<'a, E>(
) -> impl Parser<&'a [u8], (TcpDataOffset, TcpReserved), E> {
    move |bytes| {
        let (remainder, bytes) = take::<usize, &'a [u8], ()>(1usize)(bytes).unwrap();
        let (tail, data_offset) =
            nom::bits::complete::take::<&'a [u8], u8, usize, ()>(4usize)((bytes, 0)).unwrap();

        let (_, reserved) =
            nom::bits::complete::take::<&'a [u8], u8, usize, ()>(4usize)(tail).unwrap();

        Ok((
            remainder,
            (
                data_offset as u8,
                reserved as u8,
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
                    urg == 1,
                    ack == 1,
                    psh == 1,
                    rst == 1,
                    syn == 1,
                    fin == 1,
                ),
            ))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_window<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpWindow, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, tcpwindow)) => Ok((remainder, tcpwindow)),
        Err(e) => Err(e),
    }
}

fn parse_tcp_checksum<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpChecksum, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, tcpchecksum)) => Ok((remainder, tcpchecksum)),
        Err(e) => Err(e),
    }
}

fn parse_tcp_urgent_pointer<'a, E: ParseError<&'a [u8]>>(
) -> impl Parser<&'a [u8], TcpUrgentPointer, E> {
    move |input: &'a [u8]| match be_u16(input) {
        Ok((remainder, tcpurgentpointer)) => Ok((remainder, tcpurgentpointer)),
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
        Ok((remainder, options)) => {
            Ok((remainder, options.to_vec()))
        }
        Err(e) => Err(e),
    }
}

fn parse_tcp_data<'a, E: ParseError<&'a [u8]>>() -> impl Parser<&'a [u8], TcpData, E> {
    move |input: &'a [u8]| match take(input.len() as usize)(input) {
        Ok((remainder, tcp_data)) => {
            Ok((remainder, tcp_data.to_vec()))
        }
        Err(e) => Err(e),
    }
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
            src_port,
            dst_port,
            seq_number,
            ack_number,
            data_offset,
            reserved,
            urg,
            ack,
            psh,
            rst,
            syn,
            fin,
            window,
            checksum,
            urgent_pointer,
            options: options,
            data: data,
            raw_bytes: Vec::new(),
        },
    ))
}

#[cfg(test)]
mod tests {

    use super::*;

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
            raw_bytes: Vec::new(),
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
