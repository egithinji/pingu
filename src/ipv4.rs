use crate::senders::{Packet, PacketType};

const FLAGSANDOFFSET: u16 = 16384_u16;
const HEADER_LENGTH: u16 = 20;

pub struct Ipv4 {
    version: u16,
    ihl: u16,
    type_of_service: u8,
    total_length: u16,
    pub identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    pub source_address: [u8; 4],
    pub dest_address: [u8; 4],
    pub payload: Vec<u8>,
    pub raw_ip_header_bytes: Vec<u8>,
    pub entire_packet: Vec<u8>,
    pub packet_type: PacketType,
}

impl Ipv4 {
    pub fn new(source: [u8; 4], dest: [u8; 4], payload: Vec<u8>, packet_type: PacketType) -> Self {
        let mut temp = Ipv4 {
            version: 4,
            ihl: 5,
            type_of_service: 0,
            total_length: HEADER_LENGTH + payload.len() as u16,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 1,
            header_checksum: 0,
            source_address: source,
            dest_address: dest,
            payload,
            raw_ip_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
            packet_type,
        };

        temp = Ipv4::set_raw_ip_header_bytes(temp);
        temp.header_checksum = calculate_checksum(&mut temp.raw_ip_header_bytes);
        temp = Ipv4::set_raw_ip_header_bytes(temp);
        temp.entire_packet
            .extend_from_slice(&temp.raw_ip_header_bytes);
        temp.entire_packet.extend_from_slice(&temp.payload);

        temp
    }

    fn set_raw_ip_header_bytes(mut ipv4: Ipv4) -> Ipv4 {
        let mut v: Vec<u8> = Vec::new();

        //version and ihl take up 4 bits each, so combine into one octet
        let shifted_version = ipv4.version << 4;
        let word = (shifted_version + ipv4.ihl) as u8;
        v.extend_from_slice(&word.to_be_bytes());

        //type of service
        v.extend_from_slice(&ipv4.type_of_service.to_be_bytes());

        //total length
        v.extend_from_slice(&ipv4.total_length.to_be_bytes());

        //identification
        v.extend_from_slice(&ipv4.identification.to_be_bytes());

        //flags and fragment offset:
        //The flag is the first 3 bits which should be 010 signifying "Don't Fragment" and "Last
        //Fragment".
        //The fragment offset is the next 13 bits which should be all 0s. This is equivalent to
        //0bFLAGSANDOFFSET
        v.extend_from_slice(&FLAGSANDOFFSET.to_be_bytes());

        //ttl
        v.extend_from_slice(&ipv4.ttl.to_be_bytes());

        //protocol
        v.extend_from_slice(&ipv4.protocol.to_be_bytes());

        //header checksum
        v.extend_from_slice(&ipv4.header_checksum.to_be_bytes());

        //source address
        v.extend_from_slice(&ipv4.source_address);

        //destination address
        v.extend_from_slice(&ipv4.dest_address);

        ipv4.raw_ip_header_bytes = v;

        ipv4
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

impl Packet for Ipv4 {
    fn raw_bytes(&self) -> &Vec<u8> {
        &self.entire_packet
    }

    fn packet_type(&self) -> PacketType {
        self.packet_type.clone()
    }

    fn dest_address(&self) -> Option<Vec<u8>> {
        Some(self.dest_address.to_vec())
    }

    fn source_address(&self) -> Option<Vec<u8>> {
        Some(self.source_address.to_vec())
    }
}

impl<'a> TryFrom<&'a [u8]> for Ipv4 {
    type Error = &'static str;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let version: u16 = (bytes[0] & 240 as u8).checked_shr(4).unwrap() as u16;
        let ihl: u16 = (bytes[0] & 15) as u16;
        let type_of_service = bytes[1];
        let total_length: u16 = (bytes[2] as u16).checked_shl(8).unwrap() + bytes[3] as u16;
        let identification = ((bytes[4] & 240) + (bytes[5] & 15)) as u16;
        let flags: u8 = bytes[6] & 224;
        let temp1: u16 = (bytes[6] as u16) << 8 as u16;
        let temp2: u16 = temp1 + bytes[7] as u16;
        let fragment_offset: u16 = (temp2 as u16 & 8191) as u16;
        let ttl = bytes[8];
        let protocol = bytes[9];
        let header_checksum: u16 = (bytes[10] as u16).checked_shl(8).unwrap() + (bytes[11] as u16);
        let source_address: [u8; 4] = [bytes[12], bytes[13], bytes[14], bytes[15]];
        let dest_address: [u8; 4] = [bytes[16], bytes[17], bytes[18], bytes[19]];
        let start_of_data: usize = ((ihl * 32) / 8) as usize;
        let payload: Vec<u8> = bytes[start_of_data..].to_vec();
        let packet_type = match payload[0] {
            //match here as reminder to add more types, especially
            //icmpreply
            _ => PacketType::IcmpRequest,
        };

        Ok(Ipv4 {
            version,
            ihl,
            type_of_service,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_address,
            dest_address,
            payload,
            raw_ip_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
            packet_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{calculate_checksum, Ipv4};
    use crate::senders::{Packet, PacketType};

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

        let ipv4_packet = Ipv4::new(
            [192, 168, 100, 16],
            [8, 8, 8, 8],
            Vec::new(),
            PacketType::IcmpRequest,
        );

        assert_eq!(ref_bytes[0..2], ipv4_packet.raw_ip_header_bytes[0..2]);
        //skip Total Length and Identification
        assert_eq!(ref_bytes[6..10], ipv4_packet.raw_ip_header_bytes[6..10]);
        //skip Checksum
        assert_eq!(ref_bytes[12..], ipv4_packet.raw_ip_header_bytes[12..]);
    }

    #[test]
    fn valid_ipv4_packet_created_from_bytes() {
        //received_bytes are taken contents of icmp reply received from 8.8.8.8 after pinging from Linux.
        let received_bytes = &[
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
            payload: received_bytes[20..].to_vec(),
            raw_ip_header_bytes: Vec::new(),
            entire_packet: Vec::new(),
            packet_type: PacketType::IcmpRequest,
        };

        let test_ip_packet = Ipv4::try_from(received_bytes).unwrap();

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
}
