use crate::arp;
use crate::ethernet;
use crate::ipv4;
use default_net;
use pcap::{Active, Capture, Device, Error};
use std::net;
use std::time::Instant;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub enum PacketType {
    IcmpRequest,
    Arp,
}

pub trait Packet {
    fn raw_bytes(&self) -> &Vec<u8>;
    fn packet_type(&self) -> PacketType;
    fn dest_address(&self) -> Option<Vec<u8>>;
    fn source_address(&self) -> Option<Vec<u8>>;
}

pub fn raw_send(bytes: &[u8], cap: Arc<Mutex<Capture<Active>>>) -> Result<Instant, Error> {
    //get capture on device 
    //println!("Getting handle to device from raw_send...");
    //let handle = Device::list().unwrap().remove(0);
    println!("Opening capture on device...");
    //let mut cap = handle.open().unwrap();

    let mut cap = cap.lock().unwrap();

    match cap.sendpacket(bytes) {
        Ok(()) => {
            println!("Packet sent ********************************************");
            Ok(Instant::now())
        }
        Err(e) => Err(e),
    }
}

pub async fn send(
    packet: impl Packet,
    source_mac: Vec<u8>,
    cap: Arc<Mutex<Capture<Active>>>,
) -> Result<Instant, Error> {
    //if dest ip is local, do arp request to get dest mac.
    //if external, set dest mac to mac of gateway.
    let dest_ip = net::Ipv4Addr::new(
        packet.dest_address().unwrap()[0],
        packet.dest_address().unwrap()[1],
        packet.dest_address().unwrap()[2],
        packet.dest_address().unwrap()[3],
    );

    let cap2 = Arc::clone(&cap);

    let mut dest_mac: Vec<u8> = if dest_ip.is_private() {
        println!("dest ip is private, get mac of target...");
        arp::get_mac_of_target(
            &dest_ip.octets(),
            &source_mac,
            &packet.source_address().unwrap()[..],
            cap
        )
        .await
        .unwrap()
    } else {
        println!("dest ip is public, get mac of default gateway...");
        match default_net::get_default_gateway() {
            Ok(gateway) => gateway.mac_addr.octets().to_vec(),
            Err(e) => {
                panic!("Error getting default gateway:{}", e);
            }
        }
    };

    let eth_type = match packet.packet_type() {
        PacketType::IcmpRequest => [0x08, 0x00],
        PacketType::Arp => [0x08, 0x06],
    };

    let eth_packet =
        ethernet::EthernetFrame::new(&eth_type, &packet.raw_bytes(), &dest_mac, &source_mac[..]);

    raw_send(&eth_packet.raw_bytes[..], cap2)
}

#[cfg(test)]
mod tests {

    use super::send;
    use crate::icmp::IcmpRequest;
    use crate::ipv4::Ipv4;
    use crate::senders::{Packet, PacketType};
    use pcap::Device;
    use std::net;

    #[tokio::test]
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
    }
}
