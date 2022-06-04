use crate::arp;
use crate::ethernet;
use crate::ipv4;
use pcap::{Device, Error};
use std::fs::File;
use std::io::prelude::*;
use std::net;
use default_net;

const SYSFS_PATH: &'static str = "/sys/class/net/";
const SYSFS_FILENAME: &'static str = "/address";

#[derive(Clone)]
pub enum PacketType {
    IcmpRequest,
    Arp,
}

pub trait Packet {
    fn raw_bytes(&self) -> &Vec<u8>;
    fn packet_type(&self) -> PacketType;
    fn dest_address(&self) -> Option<Vec<u8>>;
    fn source_address(&self) -> Option<Vec<u8>>;
}

pub fn raw_send(bytes: &[u8], cap) -> Result<(), Error> {
    let handle = Device::list().unwrap().remove(0);
    let mut cap = handle.open().unwrap();
    cap.sendpacket(bytes)
}

pub async fn send(packet: impl Packet, source_mac: Vec<u8>) -> Result<(), Error>{
    //if the dest ip is local, do arp request to get dest mac.
    //if external, set dest mac to mac of gateway.
    let dest_ip = net::Ipv4Addr::new(
        packet.dest_address().unwrap()[0],
        packet.dest_address().unwrap()[1],
        packet.dest_address().unwrap()[2],
        packet.dest_address().unwrap()[3],
    );

    let mut dest_mac: Vec<u8> = if dest_ip.is_private() {
        println!("dest ip is private, get mac of target...");
        arp::get_mac_of_target(&dest_ip.octets()).await.unwrap()
    } else {
        match default_net::get_default_gateway() {
            Ok(gateway) => {
                gateway.mac_addr.octets().to_vec()
            },
            Err(e) => {
                panic!("Error getting default gateway:{}",e);
            }
        }
    };

    let eth_type = match packet.packet_type() {
        PacketType::IcmpRequest => [0x08, 0x00],
        PacketType::Arp => [0x08, 0x06],
    };

    let eth_packet =
        ethernet::EthernetFrame::new(&eth_type, &packet.raw_bytes(), &dest_mac, &source_mac[..]);

    raw_send(&eth_packet.raw_bytes[..])
}

pub fn get_local_mac_ip() -> (Vec<u8>, net::Ipv4Addr) {
    let mut ip_address: net::Ipv4Addr;

    let mut handle = &Device::list().unwrap()[0];
    if let net::IpAddr::V4(ip_addr) = handle.addresses[0].addr {
        ip_address = ip_addr;
    } else {
        panic!();
    }

    let file_path = format!("{}{}{}", SYSFS_PATH, handle.name, SYSFS_FILENAME);

    let mut file = File::open(file_path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mac: Vec<u8> = contents
        .strip_suffix("\n")
        .unwrap()
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect();

    (mac, ip_address)
}

#[cfg(test)]
mod tests {

    use super::get_local_mac_ip;
    use super::send;
    use crate::icmp::IcmpRequest;
    use crate::ipv4::Ipv4;
    use crate::senders::{Packet, PacketType};
    use std::net;

    #[tokio::test]
    async fn valid_packet_gets_sent_down_wire() {
        let icmp_packet = IcmpRequest::new();
        let ipv4_packet = Ipv4::new(
            [192, 168, 100, 16],
            [8, 8, 8, 8],
            icmp_packet.raw_bytes().clone(),
            PacketType::IcmpRequest,
        );
        let result = send(ipv4_packet, [0x04, 0x92, 0x26, 0x19, 0x4e, 0x4f].to_vec());

        assert!(result.await.is_ok());
    }

    #[test]
    fn returns_correct_ip_and_mac_for_default_device() {
        let correct_ip: net::Ipv4Addr = net::Ipv4Addr::new(192, 168, 100, 16);
        let correct_mac: [u8; 6] = [0x04, 0x92, 0x26, 0x19, 0x4e, 0x4f];

        let (mac, ip_addr) = get_local_mac_ip();

        assert_eq!(correct_ip, ip_addr);
        assert_eq!(&correct_mac, &mac[..]);
    }
}
