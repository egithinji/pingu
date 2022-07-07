use crate::packets::tcp::Tcp;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;

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
        let (remainder, bytes) = take::<usize, &'a [u8], ()>(1usize)(bytes).unwrap();
        let (tail, data_offset) =
            nom::bits::complete::take::<&'a [u8], u8, usize, ()>(4usize)((bytes, 0)).unwrap();

        let (_, reserved) =
            nom::bits::complete::take::<&'a [u8], u8, usize, ()>(4usize)(tail).unwrap();

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
