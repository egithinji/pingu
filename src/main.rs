use pingu::arp;
use pingu::icmp::IcmpRequest;
use pingu::ipv4;
use pingu::receivers;
use pingu::senders;
use pingu::senders::{Packet, PacketType};
use pingu::validators;
use std::env;
use std::net;
use std::thread;

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

    let (local_mac, local_ip) = senders::get_local_mac_ip();

    let icmp_packet = IcmpRequest::new();
    let ipv4_packet = ipv4::Ipv4::new(
        local_ip.octets(),
        dest_ip.octets(),
        icmp_packet.raw_bytes().clone(),
        PacketType::IcmpRequest,
    );

    //start listening for reply in dedicated thread
    //send reply when received
    let (tx, rx) = tokio::sync::oneshot::channel();
    thread::spawn(|| {
        let ethernet_packet = receivers::get_reply(cap);
        tx.send(ethernet_packet);
    });

    match senders::send(ipv4_packet, local_mac).await {
        Ok(()) => {
            println!("Packet sent successfully.")
        }
        Err(e) => {
            println!("Error sending packet to socket: {}", e);
        }
    }
}
