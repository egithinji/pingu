use pcap::{Active, Capture, Error};
use std::time::Instant;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq)]
pub enum PacketType {
    IcmpRequest,
    Arp,
    Ethernet,
}

pub trait Packet {
    fn raw_bytes(&self) -> &Vec<u8>;
    fn packet_type(&self) -> PacketType;
    fn dest_address(&self) -> Option<Vec<u8>>;
    fn source_address(&self) -> Option<Vec<u8>>;
}

pub fn raw_send(bytes: &[u8], cap: Arc<Mutex<Capture<Active>>>) -> Result<Instant, Error> {
    let mut cap = cap.lock().unwrap();
    match cap.sendpacket(bytes) {
        Ok(()) => {
            println!("Packet sent ********************************************");
            Ok(Instant::now())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {

    use crate::icmp::IcmpRequest;
    use crate::ipv4::Ipv4;
    use crate::senders::{Packet, PacketType};
    use pcap::Device;
    use std::net;

   /* #[tokio::test]
    #[ignore]
    async fn valid_packet_gets_sent_down_wire() {
        let icmp_packet = IcmpRequest::new();
        let ipv4_packet = Ipv4::new(
            [192, 168, 100, 16],
            [8, 8, 8, 8],
            icmp_packet.raw_bytes().clone(),
            PacketType::IcmpRequest,
        );

        let handle = Device::list().unwrap().remove(0);
        let mut cap = handle.open().unwrap();

        let result = send(
            ipv4_packet,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec(),
        ); //replace
           //with
           //real
           //mac
           //when
           //testing

        assert!(result.await.is_ok());
    }*/
}
