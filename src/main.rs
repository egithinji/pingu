use pingu::arp;
use pingu::ipv4;
use pingu::icmp::IcmpRequest;
use pingu::receivers;
use pingu::senders;
use pingu::senders::{Packet, PacketType};

#[tokio::main]
async fn main() {
   
    let (source_mac, local_ip) = senders::get_local_mac_ip();

    let icmp_packet = IcmpRequest::new();
    let ipv4_packet = ipv4::Ipv4::new(
        local_ip.octets(),
        //[192, 168, 100, 129],
        [8, 8, 8, 8],
        icmp_packet.raw_bytes().clone(),
        PacketType::IcmpRequest,
    );

    match senders::send(ipv4_packet, source_mac).await {
        Ok(()) => {
            println!("Packet sent successfully.")
        }
        Err(e) => {
            println!("Error sending packet to socket: {}", e);
        }
    }
}
