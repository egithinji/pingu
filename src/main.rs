use pingu::ethernet;
use pingu::icmp::IcmpRequest;
use pingu::ipv4;
use pingu::listeners;
use pingu::senders;
use pingu::senders::{Packet, PacketType};
use pingu::utilities;
use std::env;
use std::net;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

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

    //create filter to listen for replies
    let filter = format!(
        "icmp and src host {} and dst host {}",
        dest_ip.to_string(),
        local_ip.to_string()
    );

    let handle = pcap::Device::list().unwrap().remove(0);
    let mut cap = handle.open().unwrap();
    cap.filter(&filter, true).unwrap();
    cap = cap.setnonblock().unwrap();
    let cap = Arc::new(Mutex::new(cap));
    let cap2 = Arc::clone(&cap);

    //start listening for reply in dedicated thread
    //send reply when received
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        loop {
            let ethernet_packet = listeners::get_one_reply(Arc::clone(&cap));
            if ethernet_packet.is_ok() {
                tx.send(ethernet_packet);
                break;
            }
        }
    });

    let now: Instant = match senders::send(ipv4_packet, local_mac, cap2).await {
        Ok(instant) => instant,
        Err(e) => {
            panic!("Error sending packet to socket: {e}");
        }
    };

    //listen for replies and print to stdo
    //await the reply from the channel
    match rx.await {
        Ok(v) => {
            let elapsed_time = now.elapsed().as_millis();
            let e = v.unwrap();
            let ethernet_packet = ethernet::EthernetFrame::try_from(&e[..]).unwrap();
            println!(
                "Received packet from {}. Round-trip time: {:?}",
                listeners::print_reply(&ethernet_packet.raw_bytes[..]),
                elapsed_time
            );
        }
        Err(e) => {
            println!("Something bad happened:{e}");
        }
    };
}
