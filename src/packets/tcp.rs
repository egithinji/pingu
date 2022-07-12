use crate::parsers::tcp_parser::parse_tcp;
use crate::utilities::send_packet;
use crate::packets::ipv4;
use rand::{thread_rng, Rng};
use std::net;

pub struct Tcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
    pub data: Vec<u8>,
    pub raw_bytes: Vec<u8>,
}

impl Tcp {
    pub fn new(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq_number: u32,
        ack_number: u32,
        data_offset: u8,
        reserved: u8,
        urg: bool,
        ack: bool,
        psh: bool,
        rst: bool,
        syn: bool,
        fin: bool,
        window: u16,
        urgent_pointer: u16,
        options: Vec<u8>,
        data: Vec<u8>,
    ) -> Self {
        let mut temp = Tcp {
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
            checksum: 0,
            urgent_pointer,
            options,
            data,
            raw_bytes: Vec::new(),
        };

        temp = set_raw_bytes(temp);
        temp.checksum = calculate_checksum(&mut temp.raw_bytes, src_ip, dst_ip);
        temp = set_raw_bytes(temp);
        temp
    }
}

fn set_raw_bytes(mut tcp: Tcp) -> Tcp {
    let mut v: Vec<u8> = Vec::new();

    v.extend_from_slice(&tcp.src_port.to_be_bytes());
    v.extend_from_slice(&tcp.dst_port.to_be_bytes());
    v.extend_from_slice(&tcp.seq_number.to_be_bytes());
    v.extend_from_slice(&tcp.ack_number.to_be_bytes());
    //the bits in the data offset need to be shifted to leftmost position
    let shifted_data_off = tcp.data_offset << 4;
    v.extend_from_slice(&shifted_data_off.to_be_bytes());
    let flags = format!(
        "{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}",
        0,
        0,
        tcp.urg as i32,
        tcp.ack as i32,
        tcp.psh as i32,
        tcp.rst as i32,
        tcp.syn as i32,
        tcp.fin as i32
    );
    let flags = u8::from_str_radix(&flags, 2).unwrap();
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&tcp.window.to_be_bytes());
    v.extend_from_slice(&tcp.checksum.to_be_bytes());
    v.extend_from_slice(&tcp.urgent_pointer.to_be_bytes());
    v.extend_from_slice(&tcp.options);
    v.extend_from_slice(&tcp.data);

    tcp.raw_bytes = v;

    tcp
}

fn calculate_checksum(raw_bytes: &mut Vec<u8>, src_ip: [u8; 4], dst_ip: [u8; 4]) -> u16 {
    //Add the pseudo header
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&src_ip);
    bytes.extend_from_slice(&dst_ip);
    bytes.extend_from_slice(&[0]);
    bytes.extend_from_slice(&[6]); //6 is protocol field value for tcp payloads
    bytes.extend_from_slice(&(raw_bytes.len() as u16).to_be_bytes());
    bytes.extend_from_slice(raw_bytes);

    //split bytes into 16 bit chunks
    if bytes.len() % 2 != 0 {
        bytes.push(0u8)
    }; //if odd number of bytes, add one more byte of 0
       //as padding

    let transform_to_u16 = |slice: &[u8]| {
        let a: u16 = slice[0] as u16;
        let new: u16 = a << 8;
        new + slice[1] as u16
    };

    let words: Vec<u16> = bytes.chunks(2).into_iter().map(transform_to_u16).collect();

    let mut sum: u16 = 0;

    for word in words {
        let (s, overflows) = sum.overflowing_add(word);
        sum = if overflows {
            let (result, _) = sum.carrying_add(word, true);
            result
        } else {
            s
        };
    }

    !sum
}

impl<'a> TryFrom<&'a [u8]> for Tcp {
    type Error = nom::Err<nom::error::Error<&'a [u8]>>;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (_, tcp_packet) = parse_tcp(bytes)?;
        Ok(tcp_packet)
    }
}

pub struct TcpConnection {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dst_ip: [u8; 4],
    pub dst_port: u16,
    pub send_una: u32,  //oldest unacknowledged seq number
    pub send_next: u32, //next seq number to be sent
    pub seg_ack: u32,   //acknowldgment received from the other host
    pub rcv_next: u32,  //next seq number expected to be received from the other host
}

const DEFAULT_OPTIONS: [u8; 4] = [0x02, 0x04, 0x05, 0xb4]; //for simplicity, only enable one option:
                                                           //mss
const DEFAULT_WINDOW_SIZE: u16 = 64240;
impl TcpConnection {
    pub fn new(src_ip: [u8; 4], dst_ip: [u8; 4], dst_port: u16) -> Self {
        let mut rng = thread_rng();
        let random_seq: u32 = rng.gen_range(u32::MIN..u32::MAX);
        let random_src_port: u16 = rng.gen_range(32768..60999);

        TcpConnection {
            src_ip,
            src_port: random_src_port,
            dst_ip,
            dst_port,
            send_una: random_seq,
            send_next: 0,
            seg_ack: 0,
            rcv_next: 0,
        }
    }

    pub async fn send_syn(&self) {
        let tcp_packet = Tcp::new(
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.send_una,
            0,
            //20 + DEFAULT_OPTIONS.len() as u8,
            6,
            0,
            false,
            false,
            false,
            false,
            true,
            false,
            DEFAULT_WINDOW_SIZE,
            0,
            DEFAULT_OPTIONS.to_vec(),
            Vec::new(),
        );

        let ipv4_packet = ipv4::Ipv4::new(
            self.src_ip,
            self.dst_ip,
            6,
            tcp_packet.raw_bytes.clone(),
        );

        match send_packet(ipv4_packet).await {
            Ok((ip_packet, roundtrip)) => {
                println!("Received response from {:?}. Round trip time: {:?}", ip_packet.source_address,roundtrip);
            },
            Err(e) => {
                println!("Error: {e}");
            }
        };

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_initial_seq_number_generated() {
        let t = TcpConnection::new([192, 168, 100, 16], [93, 184, 216, 34], 443);
        let s1 = t.send_una;
        println!("sequence num 1: {s1}");
        let range = u32::MIN..u32::MAX;
        assert!(range.contains(&s1));
        let t2 = TcpConnection::new([192, 168, 100, 16], [93, 184, 216, 34], 443);
        let s2 = t2.send_una;
        println!("sequence num 2: {s2}");
        assert!(range.contains(&s2));
        assert_ne!(s1, s2);
    }

    #[test]
    fn random_port_number_generated() {
        let t = TcpConnection::new([192, 168, 100, 16], [93, 184, 216, 34], 443);
        let p1 = t.src_port;
        println!("port num 1: {p1}");
        let range = 32768..60999;
        assert!(range.contains(&p1));
        let t2 = TcpConnection::new([192, 168, 100, 16], [93, 184, 216, 34], 443);
        let p2 = t2.src_port;
        println!("port num 2: {p2}");
        assert!(range.contains(&p2));
        assert_ne!(p1, p2);
    }

    #[test]
    fn valid_tcp_packet_created() {
        //Beware of https://wiki.wireshark.org/CaptureSetup/Offloading#linux which may affect
        //checksum displayed on wireshark.

        //Ref bytes are wireshark capture of tcp connection to example.com from ip address
        //192.168.100.16
        let ref_bytes = [
            0xaa, 0x10, 0x01, 0xbb, 0xa8, 0x32, 0x07, 0x89, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0xfa, 0xf0, 0xc1, 0x23, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x2e, 0x46, 0xa7, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];

        let tcp_packet = Tcp::new(
            [192, 168, 100, 16],
            [93, 184, 216, 34],
            43536,
            443,
            2821851017,
            0,
            10,
            0,
            false,
            false,
            false,
            false,
            true,
            false,
            64240,
            0,
            [
                0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x2e, 0x46, 0xa7, 0x8a, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
            ]
            .to_vec(),
            Vec::new(),
        );
        assert_eq!(&ref_bytes, &tcp_packet.raw_bytes[..]);
    }
}
