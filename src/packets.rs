use crate::senders::Packet;
use crate::senders::PacketType;

const TOTAL_LENGTH: u16 = 8 + (DATA.len() as u16); //ICMP Header + Data
                                                        //const DATA: [u8;18] = [106, 111, 110, 32, 112, 111, 115, 116, 101, 108,32,32,32,32,32,32,32,32];
const DATA: [u8; 48] = [
    0x1b, 0x2f, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
];

pub struct IcmpRequest {
    icmp_type: u8,
    code: u8,
    icmp_checksum: u16,
    identifier: u16,
    sequence_number: u16,
    data: [u8; 48],
    pub raw_icmp_bytes: Vec<u8>,
}

impl IcmpRequest {
    pub fn new() -> Self {
        let mut temp = IcmpRequest {
            icmp_type: 8,
            code: 0,
            icmp_checksum: 0,
            identifier: 0,
            sequence_number: 0,
            data: DATA,
            raw_icmp_bytes: Vec::new(),
        };

        temp = IcmpRequest::set_raw_icmp_bytes(temp);
        temp.icmp_checksum = calculate_checksum(&mut temp.raw_icmp_bytes);
        temp = IcmpRequest::set_raw_icmp_bytes(temp);
        temp
    }
    
    fn set_raw_icmp_bytes(mut icmp: IcmpRequest) -> IcmpRequest {
        let mut v: Vec<u8> = Vec::new();

        //type
        v.extend_from_slice(&icmp.icmp_type.to_be_bytes());

        //code
        v.extend_from_slice(&icmp.code.to_be_bytes());

        //checksum
        v.extend_from_slice(&icmp.icmp_checksum.to_be_bytes());

        //identifier
        v.extend_from_slice(&icmp.identifier.to_be_bytes());

        //sequence number
        v.extend_from_slice(&icmp.sequence_number.to_be_bytes());

        //data
        v.extend_from_slice(&icmp.data);

        icmp.raw_icmp_bytes = v;

        icmp
    }
}

fn calculate_checksum(bytes: &mut Vec<u8>) -> u16 {
    //split bytes into 16 bit chunks
    if bytes.len() % 2 != 0 {
        bytes.push(0_u8)
    }; //if odd number of bytes, add one more byte of 0
       //as padding
    let v: Vec<&[u8]> = bytes.chunks(2).collect();

    let transform_to_u16 = |slice: &[u8]| {
        let a: u16 = slice[0] as u16;
        let new: u16 = a << 8;
        new + slice[1] as u16
    };

    let words: Vec<u16> = v.into_iter().map(transform_to_u16).collect();

    let mut sum: u16 = 0;

    for i in 0..words.len() {
        let (s, overflows) = sum.overflowing_add(words[i]);
        sum = if overflows {
            let (result, _) = sum.carrying_add(words[i], true);
            result
        } else {
            s
        };
    }

    let sum = !sum;
    sum
}

impl Packet for IcmpRequest {
    fn raw_bytes(&self) -> &Vec<u8> {
        &self.raw_icmp_bytes
    }

    fn packet_type(&self) -> PacketType {
        PacketType::IcmpRequest        
    }
}

#[cfg(test)]
mod tests {

    use super::{calculate_checksum, IcmpRequest};

    #[test]
    fn raw_icmp_bytes_works() {
        //The ref_bytes reference test data is the ICMP Header byte sequence generated by Ping in Linux when
        //pinging 8.8.8.8.
        //The following bytes will be skipped while testing:
        //  -> ICMP Checksum, Identifier, Sequence Number, and Timestamp

        let ref_bytes: [u8; 64] = [
            0x08, 0x00, 0x0c, 0x17, 0x72, 0xe8, 0x00, 0x01, 0x08, 0x9b, 0x8b, 0x62, 0x00, 0x00,
            0x00, 0x00, 0x1b, 0x2f, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
            0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];

        let icmp_request = IcmpRequest::new();

        assert_eq!(ref_bytes[0..2], icmp_request.raw_icmp_bytes[0..2]);
        //skip Checksum, Identifier, Sequence Number, and Timestamp
        assert_eq!(ref_bytes[16..], icmp_request.raw_icmp_bytes[8..]);
    }

    #[test]
    #[ignore]
    fn calculate_checksum_works() {
    
        unimplemented!();

    }
}
