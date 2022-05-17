#![feature(bigint_helper_methods)]

const FLAGSANDOFFSET: u16 = 16384_u16;
const TOTAL_LENGTH: u16 = 38;

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
    source_address: [u8; 4],
    dest_address: [u8; 4],
    icmp_type: u8,
    code: u8,
    icmp_checksum: u16,
    identifier: u16,
    sequence_number: u16,
    data: [u8; 10],
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
            total_length: 38,
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
            data: [106, 111, 110, 32, 112, 111, 115, 116, 101, 108],
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


#[cfg(test)]
mod tests {

    use super::{calculate_checksum, IcmpRequest};

    #[test]
    fn raw_ip_bytes_works() {
        //Expected header bytes are based on the following field assumptions:
        //version = 4
        //ihl = 5
        //type_of_service = 0
        //total_length = 41
        //identification = 0
        //flags_and_fragment = 16384
        //ttl = 50
        //protocol = 1
        //header_checksum = 0
        //source_address = 192.168.100.16
        //dest_address = 8.8.8.8

        let expected_header_bytes: Vec<u8> = vec![
            69, 0, 0, 41, 0, 0, 64, 0, 50, 1, 0, 0, 192, 168, 100, 16, 8, 8, 8, 8,
        ];

        let mut test_icmp = IcmpRequest {
            version: 4,
            ihl: 5,
            type_of_service: 0,
            total_length: 41,
            identification: 0,
            flags: 0,           //doesn't matter will be changed in new()
            fragment_offset: 0, //doesn't matter will be changed in new()
            ttl: 50,
            protocol: 1,
            header_checksum: 0,
            source_address: [192, 168, 100, 16],
            dest_address: [8, 8, 8, 8],
            icmp_type: 8,
            code: 0,
            icmp_checksum: 0,
            identifier: 0,
            sequence_number: 0,
            data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            raw_icmp_bytes: Vec::new(),
            raw_ip_bytes: Vec::new(),
            entire_packet: Vec::new(),
        };

        test_icmp = IcmpRequest::set_raw_ip_bytes(test_icmp);

        assert_eq!(expected_header_bytes, test_icmp.raw_ip_bytes);
    }

    #[test]
    fn raw_icmp_bytes_works() {
        //Expected icmp_bytes based on the following assumptions:
        //icmp_type: 8
        //code: 0
        //icmp_checksum: 0
        //identifier: 0
        //sequence_number: 0
        //data: "jon postel" i.e. [106, 111, 110, 32, 112, 111, 115, 116, 101, 108]

        let expected_icmp_bytes: Vec<u8> = vec![
            8, 0, 0, 0, 0, 0, 0, 0, 106, 111, 110, 32, 112, 111, 115, 116, 101, 108,
        ];

        let mut test_icmp = IcmpRequest {
            version: 4,
            ihl: 5,
            type_of_service: 0,
            total_length: 41,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 50,
            protocol: 1,
            header_checksum: 0,
            source_address: [192, 168, 100, 16],
            dest_address: [8, 8, 8, 8],
            icmp_type: 8,
            code: 0,
            icmp_checksum: 0,
            identifier: 0,
            sequence_number: 0,
            data: [106, 111, 110, 32, 112, 111, 115, 116, 101, 108],
            raw_icmp_bytes: Vec::new(),
            raw_ip_bytes: Vec::new(),
            entire_packet: Vec::new(),
        };

        test_icmp = IcmpRequest::set_raw_icmp_bytes(test_icmp);

        assert_eq!(expected_icmp_bytes, test_icmp.raw_icmp_bytes);
    }

    #[test]
    fn calculate_checksum_works() {
        let mut test_icmp = IcmpRequest {
            version: 4,
            ihl: 5,
            type_of_service: 0,
            total_length: 84,
            identification: 24499,
            flags: 0,           /*will be set automatically*/
            fragment_offset: 0, /*will be set automatically*/
            ttl: 64,
            protocol: 1,
            header_checksum: 0,
            source_address: [192, 168, 100, 16],
            dest_address: [8, 8, 8, 8],
            icmp_type: 8,
            code: 0,
            icmp_checksum: 0,
            identifier: 0,
            sequence_number: 0,
            data: [106, 111, 110, 32, 112, 111, 115, 116, 101, 108],
            raw_icmp_bytes: Vec::new(),
            raw_ip_bytes: Vec::new(),
            entire_packet: Vec::new(),
        };

        let wireshark_checksum = 42541;
        test_icmp = IcmpRequest::set_raw_ip_bytes(test_icmp);

        assert_eq!(
            wireshark_checksum,
            calculate_checksum(&mut test_icmp.raw_ip_bytes)
        );
    }
}
