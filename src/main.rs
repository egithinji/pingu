use pingu::arp;
use pingu::ethernet;
use pingu::icmp::IcmpRequest;
use pingu::ipv4;
use pingu::senders::{Packet, PacketType};
use pingu::utilities;
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

    utilities::single_pingu(dest_ip).await;
}
