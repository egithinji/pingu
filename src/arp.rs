use crate::senders::Packet;
use crate::senders::PacketType;

pub struct ArpRequest {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: [u8;6],
    spa: [u8;4],
    tha: [u8;6],
    tpa: [u8;4],
    pub raw_bytes: Vec<u8>,
}

impl ArpRequest {
    pub fn new(local_mac: [u8;6], local_ip: [u8;4], dest_ip: [u8;4]) -> Self {
        let mut temp = ArpRequest {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            oper: 1,
            sha: local_mac,
            spa: local_ip,
            tha: [0,0,0,0,0,0],
            tpa: dest_ip,
            raw_bytes: Vec::new(),
        };

       ArpRequest::set_raw_bytes(&mut temp);
       temp
            
    }

    fn set_raw_bytes(arp_request: &mut ArpRequest) {

        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&arp_request.htype.to_be_bytes());
        v.extend_from_slice(&arp_request.ptype.to_be_bytes());
        v.extend_from_slice(&arp_request.hlen.to_be_bytes());
        v.extend_from_slice(&arp_request.plen.to_be_bytes());
        v.extend_from_slice(&arp_request.oper.to_be_bytes());
        v.extend_from_slice(&arp_request.sha);
        v.extend_from_slice(&arp_request.spa);
        v.extend_from_slice(&arp_request.tha);
        v.extend_from_slice(&arp_request.tpa);

        arp_request.raw_bytes = v;

    }
}

impl Packet for ArpRequest {
    fn raw_bytes(&self) -> &Vec<u8> {
        &self.raw_bytes
    }

    fn packet_type(&self) -> PacketType {
        PacketType::Arp
    }
}


#[cfg(test)]
mod tests {
    use super::ArpRequest;

    #[test]
    fn generates_valid_arp_request() {
        //Reference bytes are the bytes as captured by wireshark for an arp request generated on
        //the local network by a linux machine. The request is by a host with IP 192.168.100.16
        //looking for 192.168.100.97. This is just the arp request portion.

        let ref_bytes: [u8; 28] = [0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
  0x04, 0x92, 0x26, 0x19, 0x4e, 0x4f, 0xc0, 0xa8,
  0x64, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0xa8, 0x64, 0x61];

        let local_mac: [u8;6] = [0x04,0x92,0x26,0x19,0x4e,0x4f];
        let local_ip: [u8;4] = [192,168,100,16];
        let dest_ip: [u8;4] = [192,168,100,97];
 
        let arp_request: ArpRequest = ArpRequest::new(local_mac,local_ip,dest_ip);

        assert_eq!(&arp_request.raw_bytes[..],ref_bytes);

    }
}
