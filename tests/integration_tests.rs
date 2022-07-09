use pingu::utilities;
use pingu::packets::{ipv4,icmp::IcmpRequest};
use std::net;

#[tokio::test]
#[ignore]
pub async fn single_external_pingu_receives_reply() {

        let dest_ip: net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        let icmp_request = IcmpRequest::new(); 
        let ipv4_packet: ipv4::Ipv4 = icmp_request.send(dest_ip).await.unwrap(); 

        assert_eq!(ipv4_packet.source_address,dest_ip.octets());
}

#[tokio::test]
#[ignore]
pub async fn single_internal_pingu_receives_reply() {

        let dest_ip: net::Ipv4Addr = "192.168.100.129".parse().unwrap();
        let icmp_request = IcmpRequest::new();
        let ipv4_packet: ipv4::Ipv4 = icmp_request.send(dest_ip).await.unwrap(); 

        assert_eq!(ipv4_packet.source_address,dest_ip.octets());
}
