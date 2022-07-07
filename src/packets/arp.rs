use crate::senders::Packet;
use crate::packets::ethernet;
use crate::utilities;
use nom::error::ParseError;
use crate::parsers::arp_parser::parse_arp;

pub struct ArpRequest<'a> {
    pub htype: u16,    //hardware type
    pub ptype: u16,    //protocol type
    pub hlen: u8,      //hardware address length
    pub plen: u8,      //protocol address length
    pub oper: u16, //operation
    pub sha: &'a [u8], //sender hardware address
    pub spa: &'a [u8], //sender protocol address
    pub tha: &'a [u8], //target hardware address
    pub tpa: &'a [u8], //target protocol address
    pub raw_bytes: Vec<u8>,
}

impl<'a> ArpRequest<'a> {
    pub fn new(local_mac: &'a [u8], local_ip: &'a [u8], dest_ip: &'a [u8]) -> Self {
        let mut temp = ArpRequest {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            oper: 1,
            sha: local_mac,
            spa: local_ip,
            tha: &[0, 0, 0, 0, 0, 0],
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
        v.extend_from_slice(arp_request.sha);
        v.extend_from_slice(arp_request.spa);
        v.extend_from_slice(arp_request.tha);
        v.extend_from_slice(arp_request.tpa);

        arp_request.raw_bytes = v;
    }
}

impl<'a> Packet for ArpRequest<'a> {
    fn raw_bytes(&self) -> &Vec<u8> {
        &self.raw_bytes
    }

    fn dest_address(&self) -> Option<Vec<u8>> {
        Some(self.tpa.to_vec())
    }

    fn source_address(&self) -> Option<Vec<u8>> {
        Some(self.spa.to_vec())
    }
}

//Todo: Move this function to utilities.rs
pub async fn get_mac_of_target(
    target_ip: &[u8],
    source_mac: &[u8],
    source_ip: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let arp_request = ArpRequest::new(source_mac, source_ip, target_ip);

    //send the packet
    let eth_packet = ethernet::EthernetFrame::new(
        &[0x08, 0x06],
        arp_request.raw_bytes(),
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        source_mac,
    );

    match utilities::request_and_response(eth_packet).await {
        Ok((response, _)) => {
            let arp_reply = ethernet::EthernetFrame::try_from(&response[..]).unwrap();
            Ok(arp_reply.source_mac.to_vec())
        },
        Err(e) => {
            Err(e)
        }
    }

}

impl<'a> TryFrom<&'a [u8]> for ArpRequest<'a> {
    type Error = nom::Err<nom::error::Error<&'a [u8]>>;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (_, arp_packet) = parse_arp(bytes)?;
        Ok(arp_packet)
    }
}

#[cfg(test)]
mod tests {
    use super::{get_mac_of_target, ArpRequest};
    use crate::utilities::{get_local_mac_ip, get_wireshark_bytes};

    #[test]
    fn generates_valid_arp_request() {
        let ref_bytes: [u8; 28] = get_wireshark_bytes("test_valid_arp_request_data.txt")
            .try_into()
            .unwrap();
        let (local_mac, _) = get_local_mac_ip();
        let local_mac: [u8; 6] = local_mac.try_into().unwrap();
        let local_ip: [u8; 4] = [192, 168, 100, 16];
        let dest_ip: [u8; 4] = [192, 168, 100, 97];

        let arp_request: ArpRequest = ArpRequest::new(&local_mac, &local_ip, &dest_ip);

        assert_eq!(&arp_request.raw_bytes[..], ref_bytes);
    }

    #[tokio::test]
    #[ignore]
    async fn gets_correct_mac_based_on_ip() {
        let target_ip = [192, 168, 100, 129];
        let target_mac: [u8; 6] = get_wireshark_bytes("test_target_mac.txt")
            .try_into()
            .unwrap();

        let (source_mac, _) = get_local_mac_ip();
        let source_mac: [u8; 6] = source_mac.try_into().unwrap();

        let source_ip = [192, 168, 100, 16];

        let mac: &[u8] = &get_mac_of_target(&target_ip, &source_mac, &source_ip)
            .await
            .unwrap();

        assert_eq!(&target_mac, mac);
    }

    }
