use pcap::Device;
use pingu::icmp::IcmpRequest;
use pingu::ipv4;
use pingu::receivers;
use pingu::senders;
use pingu::senders::{Packet, PacketType};
use pingu::ethernet;
use std::env;
use std::net;
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

    let (local_mac, local_ip) = senders::get_local_mac_ip();

    let icmp_packet = IcmpRequest::new();
    let ipv4_packet = ipv4::Ipv4::new(
        local_ip.octets(),
        dest_ip.octets(),
        icmp_packet.raw_bytes().clone(),
        PacketType::IcmpRequest,
    );

    //get an active capture on first device
    let device = Device::list().unwrap().remove(0);
    let mut cap = device.open().unwrap();

    //create filter to listen for replies
    let filter = format!(
        "icmp and src host {} and dst host {}",
        dest_ip.to_string(),
        local_ip.to_string()
    );

    cap.filter(&filter, true).unwrap();

    //start listening for reply in dedicated thread
    //send reply when received
    let (tx, rx) = tokio::sync::oneshot::channel();
    thread::spawn(|| {
        let ethernet_packet = receivers::get_reply(cap);
        tx.send(ethernet_packet);
    });

    //get capture on same device as above
    //this is a temporary fix. Will need to find way of sharing same cap.
    let handle = Device::list().unwrap().remove(0);
    let mut cap2 = handle.open().unwrap();

    //start the timer
    //let now = Instant::now();
    let now: Instant = match senders::send(ipv4_packet, local_mac, cap2).await {
        Ok(instant) => {
            //println!("Packet sent successfully.")
            instant
        }
        Err(e) => {
            //println!("Error sending packet to socket: {}", e);
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
            println!("Received packet from {}. Round-trip time: {:?}",receivers::print_reply(&ethernet_packet.raw_bytes[..]),elapsed_time);
        },
        Err(e) => {
            println!("Something bad happened:{e}");
        }
    };
}
