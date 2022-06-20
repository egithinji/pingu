use crate::senders::Packet;
use crate::senders::PacketType;
use crate::{ethernet, utilities};

pub struct ArpRequest<'a> {
    htype: u16,    //hardware type
    ptype: u16,    //protocol type
    hlen: u8,      //hardware address length
    plen: u8,      //protocol address length
    pub oper: u16, //operation
    pub sha: &'a [u8],
    spa: &'a [u8],
    tha: &'a [u8],
    tpa: &'a [u8],
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

    fn packet_type(&self) -> PacketType {
        PacketType::Arp
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
    type Error = &'static str;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let htype: u16 = (bytes[0] as u16).checked_shl(8).unwrap() + bytes[1] as u16;
        let ptype: u16 = (bytes[2] as u16).checked_shl(8).unwrap() + bytes[3] as u16;
        let hlen: u8 = bytes[4];
        let plen: u8 = bytes[5];
        let oper: u16 = (bytes[6] as u16).checked_shl(8).unwrap() + bytes[7] as u16;

        Ok(ArpRequest {
            htype,
            ptype,
            hlen,
            plen,
            oper,
            sha: &bytes[8..14],
            spa: &bytes[14..18],
            tha: &bytes[18..24],
            tpa: &bytes[24..28],
            raw_bytes: Vec::new(),
        })
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

    #[test]
    fn valid_arp_packet_created_from_bytes() {
        let received_bytes = &get_wireshark_bytes("test_arp_reply_bytes.txt")[..];

        let (tha, _) = get_local_mac_ip();
        let tha: [u8; 6] = tha.try_into().unwrap();
        let sha: [u8; 6] = get_wireshark_bytes("test_target_mac.txt")
            .try_into()
            .unwrap();

        let expected = ArpRequest {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            oper: 2, //coz we're capturing a reply not a request
            sha: &sha,
            spa: &[192, 168, 100, 129],
            tha: &tha,
            tpa: &[192, 168, 100, 16],
            raw_bytes: Vec::new(),
        };

        let test_arp_packet = ArpRequest::try_from(received_bytes).unwrap();

        assert_eq!(test_arp_packet.htype, expected.htype);
        assert_eq!(test_arp_packet.ptype, expected.ptype);
        assert_eq!(test_arp_packet.hlen, expected.hlen);
        assert_eq!(test_arp_packet.plen, expected.plen);
        assert_eq!(test_arp_packet.oper, expected.oper);
        assert_eq!(test_arp_packet.sha, expected.sha);
        assert_eq!(test_arp_packet.spa, expected.spa);
        assert_eq!(test_arp_packet.tha, expected.tha);
        assert_eq!(test_arp_packet.tpa, expected.tpa);
    }
}
