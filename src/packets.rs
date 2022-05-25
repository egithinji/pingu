use crate::senders::Packet;
use crate::senders::PacketType;

const FLAGSANDOFFSET: u16 = 16384_u16;
const TOTAL_LENGTH: u16 = 20 + 8 + (DATA.len() as u16); //IP Header + ICMP Header + Data
                                                        //const DATA: [u8;18] = [106, 111, 110, 32, 112, 111, 115, 116, 101, 108,32,32,32,32,32,32,32,32];
const DATA: [u8; 48] = [
    0x1b, 0x2f, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
];

pub struct IcmpRequest {
    version: u16,
    ihl: u16,
    type_of_service: u8,
    total_length: u16,
    identification: u16,
    flags: u8,            /*make this private*/
    fragment_offset: u16, /*make this private*/
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    pub source_address: [u8; 4],
    pub dest_address: [u8; 4],
    icmp_type: u8,
    code: u8,
    icmp_checksum: u16,
    identifier: u16,
    sequence_number: u16,
    data: [u8; 48],
    pub raw_icmp_bytes: Vec<u8>,
    pub raw_ip_bytes: Vec<u8>,
    pub entire_packet: Vec<u8>,
}

impl IcmpRequest {
    pub fn new(source: [u8; 4], dest: [u8; 4]) -> Self {
        let mut temp = IcmpRequest {
            version: 4,
            ihl: 5,
            type_of_service: 0,
            total_length: TOTAL_LENGTH,
            identification: 0,
            flags: 0, /*make this private. the byte representation will be set with raw_ip_bytes()*/
            fragment_offset: 0, /*make this private. the byte representation will be set with raw_ip_bytes()*/
            ttl: 64,
            protocol: 1,
            header_checksum: 0,
            source_address: source,
            dest_address: dest,
            icmp_type: 8,
            code: 0,
            icmp_checksum: 0,
            identifier: 0,
            sequence_number: 0,
            data: DATA,
            raw_icmp_bytes: Vec::new(),
            raw_ip_bytes: Vec::new(),
            entire_packet: Vec::new(),
        };

        temp = IcmpRequest::set_raw_icmp_bytes(temp);
        temp.icmp_checksum = calculate_checksum(&mut temp.raw_icmp_bytes);
        temp = IcmpRequest::set_raw_icmp_bytes(temp);
        temp = IcmpRequest::set_raw_ip_bytes(temp);
        temp.header_checksum = calculate_checksum(&mut temp.raw_ip_bytes);
        temp = IcmpRequest::set_raw_ip_bytes(temp);
        temp.entire_packet.extend_from_slice(&temp.raw_ip_bytes);
        temp.entire_packet.extend_from_slice(&temp.raw_icmp_bytes);

        temp
    }

    fn set_raw_ip_bytes(mut icmp: IcmpRequest) -> IcmpRequest {
        let mut v: Vec<u8> = Vec::new();

        //version and ihl take up 4 bits each, so combine into one octet
        let shifted_version = icmp.version << 4;
        let word = (shifted_version + icmp.ihl) as u8;
        v.extend_from_slice(&word.to_be_bytes());

        //type of service
        v.extend_from_slice(&icmp.type_of_service.to_be_bytes());

        //total length
        v.extend_from_slice(&icmp.total_length.to_be_bytes());

        //identification
        v.extend_from_slice(&icmp.identification.to_be_bytes());

        //flags and fragment offset:
        //The flag is the first 3 bits which should be 010 signifying "Don't Fragment" and "Last
        //Fragment".
        //The fragment offset is the next 13 bits which should be all 0s. This is equivalent to
        //0bFLAGSANDOFFSET
        v.extend_from_slice(&FLAGSANDOFFSET.to_be_bytes());

        //ttl
        v.extend_from_slice(&icmp.ttl.to_be_bytes());

        //protocol
        v.extend_from_slice(&icmp.protocol.to_be_bytes());
        println!("Protocol as bytes: {:?}", &icmp.protocol.to_be_bytes());

        //header checksum
        v.extend_from_slice(&icmp.header_checksum.to_be_bytes());

        //source address
        v.extend_from_slice(&icmp.source_address);

        //destination address
        v.extend_from_slice(&icmp.dest_address);

        icmp.raw_ip_bytes = v;

        icmp
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
        &self.entire_packet
    }

    fn packet_type(&self) -> PacketType {
        PacketType::IcmpRequest        
    }
    
}

#[cfg(test)]
mod tests {

    use super::{calculate_checksum, IcmpRequest};

    #[test]
    fn raw_ip_bytes_works() {
        //The ref_bytes reference test data is the IP Header byte sequence generated by Ping in Linux when
        //pinging 8.8.8.8.
        //The following bytes will be skipped while testing:
        //  -> Total Length and Identification
        //  -> Checksum

        let ref_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x54, 0x3f, 0x4f, 0x40, 0x00, 0x40, 0x01, 0xc6, 0x91, 0xc0, 0xa8,
            0x64, 0x10, 0x08, 0x08, 0x08, 0x08,
        ];

        let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);

        assert_eq!(ref_bytes[0..2], icmp_request.raw_ip_bytes[0..2]);
        //skip Total Length and Identification
        assert_eq!(ref_bytes[6..10], icmp_request.raw_ip_bytes[6..10]);
        //skip Checksum
        assert_eq!(ref_bytes[12..], icmp_request.raw_ip_bytes[12..]);
    }

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

        let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);

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
