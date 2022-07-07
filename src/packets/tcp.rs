use crate::parsers::parse_tcp;
use rand::{thread_rng, Rng};

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
    pub raw_tcp_header_bytes: Vec<u8>,
    pub entire_packet: Vec<u8>,
}

impl Tcp {
//    pub fn new
}

impl<'a> TryFrom<&'a [u8]> for Tcp {
    type Error = nom::Err<nom::error::Error<&'a [u8]>>;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (_, tcp_packet) = parse_tcp(bytes)?;
        Ok(tcp_packet)
    }
}

pub struct TcpConnection {
    pub send_una: u32, //oldest unacknowledged seq number
    pub send_next: u32, //next seq number to be sent
    pub seg_ack: u32, //acknowldgment received from the other host
    pub rcv_next: u32, //next seq number expected to be received from the other host
}

impl TcpConnection {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let random_seq: u32 = rng.gen_range(u32::MIN..u32::MAX);

        TcpConnection {
            send_una: random_seq,
            send_next: 0,
            seg_ack: 0,
            rcv_next: 0,
        }

    }


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_initial_seq_number_generated() {
        let t = TcpConnection::new();
        let s1 = t.send_una;
        println!("sequence num 1: {s1}");
        let range = u32::MIN..u32::MAX;
        assert!(range.contains(&s1));
        let t2 = TcpConnection::new();
        let s2 = t2.send_una;
        println!("sequence num 2: {s2}");
        assert!(range.contains(&s2));
        assert_ne!(s1,s2); 
    }

}
