use pingu::arp;
use pingu::ipv4;
use pingu::icmp::IcmpRequest;
use pingu::receivers;
use pingu::senders;
use pingu::senders::{Packet, PacketType};

#[tokio::main]
async fn main() {
    
    let icmp_packet = IcmpRequest::new();
    let ipv4_packet = ipv4::Ipv4::new(
        [192, 168, 100, 16],
        [192, 168, 100, 129],
        //[8, 8, 8, 8],
        icmp_packet.raw_bytes().clone(),
        PacketType::IcmpRequest,
    );

    match senders::send(ipv4_packet).await {
        Ok(()) => {
            println!("Packet sent successfully.")
        }
        Err(e) => {
            println!("Error sending packet to socket: {}", e);
        }
    }
}
