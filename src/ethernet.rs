use crc32fast;

const PREAMBLE_AND_SFD: [u8;8] = [0xAAu8.to_be(),0xAAu8.to_be(),0xAAu8.to_be(),0xAAu8.to_be(),0xAAu8.to_be(),0xAAu8.to_be(),0xAAu8.to_be(),0xABu8.to_be()];

pub struct EthernetFrame{
    dest_mac: [u8;6],
    source_mac: [u8;6],
    length: [u8;2],
    payload: Vec<u8>,
    fcs: [u8;4],
    pub raw_bytes: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(payload: Vec<u8>, dest_mac: [u8;6], source_mac: [u8;6]) -> Self {

        /*if payload.len() < 46 {
            unimplemented!();
        }*/

        let mut temp = EthernetFrame {
            dest_mac,
            source_mac,
            //length: (payload.len() as u16).to_ne_bytes(),
            length: [0x08u8,0x00u8],
            payload,
            fcs: [0,0,0,0],
            raw_bytes: Vec::new(),
        };
       
      EthernetFrame::set_raw_bytes(&mut temp);
      temp.fcs = get_fcs(&temp.raw_bytes);
      EthernetFrame::set_raw_bytes(&mut temp);

      temp

    }

    fn set_raw_bytes(ether: &mut EthernetFrame) {

        //Todo: confirm whether necessary to reverse endianness

        let mut v: Vec<u8> = Vec::new();
        //v.extend_from_slice(&PREAMBLE_AND_SFD);
        v.extend_from_slice(&ether.dest_mac);
        v.extend_from_slice(&ether.source_mac);
        v.extend_from_slice(&ether.length);
        v.extend_from_slice(&ether.payload);
        v.extend_from_slice(&ether.fcs);

        ether.raw_bytes = v;
    }
}

fn get_fcs(bytes: &Vec<u8>) -> [u8;4]{

    //crc32fast::hash(&bytes[8..bytes.len()]).to_be_bytes()
    crc32fast::hash(&bytes[0..bytes.len()-4]).to_be_bytes()
    
}


