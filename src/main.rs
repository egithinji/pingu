use pingu::packets::{arp,ethernet,icmp::IcmpRequest,ipv4,tcp::TcpConnection,tcp::Tcp};
use pingu::senders::{Packet};
use pingu::utilities;
use std::env;
use std::net;

#[tokio::main]
async fn main() {
/*
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
*/

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        panic!("Please enter the source and destination IP addresses and dest port.");
    }

    let src_ip: net::Ipv4Addr = match args[1].parse() {
        Ok(a) => a,
        Err(e) => {
            panic!("An error occurred: {e}");
        }
    };

    let dst_ip: net::Ipv4Addr = match args[2].parse() {
        Ok(a) => a,
        Err(e) => {
            panic!("An error occurred: {e}");
        }
    };

    let dst_port: u16 = match args[3].parse() {
        Ok(a) => a,
        Err(e) => {
            panic!("An error occurred: {e}");
        }
    };

    let tcp_connection = TcpConnection::new(src_ip.octets(), dst_ip.octets(), dst_port);
    tcp_connection.send_syn().await;

}
