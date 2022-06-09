use pingu::arp;
use pingu::ethernet;
use pingu::icmp::IcmpRequest;
use pingu::ipv4;
use pingu::utilities;
use pingu::senders::{Packet, PacketType};
use std::env;
use std::net;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please enter the destination IP address.");
    }

    let dest_ip: net::Ipv4Addr = match args[1].parse() {
        Ok(a) => a,
        Err(e) => {
            panic!("An error occurred: {e}");
        }
    };

    let (local_mac, local_ip) = utilities::get_local_mac_ip();

    let icmp_packet = IcmpRequest::new();
    let ipv4_packet = ipv4::Ipv4::new(
        local_ip.octets(),
        dest_ip.octets(),
        icmp_packet.raw_bytes().clone(),
        PacketType::IcmpRequest,
    );

    let dest_mac: Vec<u8> = if dest_ip.is_private() {
        println!("dest ip is private, get mac of target...");
        arp::get_mac_of_target(&dest_ip.octets(), &local_mac, &local_ip.octets())
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

    let eth_packet = ethernet::EthernetFrame::new(
        &[0x08, 0x00],
        ipv4_packet.raw_bytes(),
        &dest_mac,
        &local_mac[..],
    );

    let (response, roundtrip) = utilities::request_and_response(eth_packet).await.unwrap();

    let ethernet_packet = ethernet::EthernetFrame::try_from(&response[..]).unwrap();
    println!(
        "Received packet from {}. Round-trip time: {}",
        utilities::print_reply(&ethernet_packet.raw_bytes[..]),
        roundtrip
    );
}
