use pingu::packets::{arp,ethernet,icmp::IcmpRequest,ipv4,tcp::TcpConnection,tcp::Tcp};
use pingu::utilities::Packet;
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

    let icmp_request = IcmpRequest::new();
    let ip_packet = ipv4::Ipv4::new([10,0,1,2],[8,8,8,8],1,icmp_request.raw_bytes().clone());
    utilities::tun_send(ip_packet).await;*/

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

    let mut tcp_connection = TcpConnection::new(src_ip.octets(), dst_ip.octets(), dst_port);
    tcp_connection.do_handshake().await;

}
