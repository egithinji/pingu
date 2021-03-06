use crate::packets::arp;
use crate::packets::ethernet;
use crate::packets::ipv4;
use pcap;
use pcap::Device;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::process::Command;
use tun_tap::{Iface,Mode};
use std::thread;
use std::time::Duration;

const SYSFS_PATH: &str = "/sys/class/net/";
const SYSFS_FILENAME: &str = "/address";

pub trait Packet {
    fn raw_bytes(&self) -> &Vec<u8>;
    fn dest_address(&self) -> Option<Vec<u8>>;
    fn source_address(&self) -> Option<Vec<u8>>;
}

pub async fn send_packet(ip_packet: ipv4::Ipv4) -> Result<(ipv4::Ipv4, u128), &'static str> {
    let (local_mac, _) = get_local_mac_ip();

    let dest_ip: net::Ipv4Addr = ip_packet.dest_address.try_into().unwrap();

    let dest_mac: Vec<u8> = if dest_ip.is_private() {
        println!("dest ip is private, get mac of target...");
        match arp::get_mac_of_target(&dest_ip.octets(), &local_mac, &ip_packet.source_address).await {
            Ok(dmac) => dmac,
            Err(e) => {
                println!("{e}");
                return Err(e);
            }
        }
    } else {
        println!("dest ip is public, get mac of default gateway...");
        match default_net::get_default_gateway() {
            Ok(gateway) => gateway.mac_addr.octets().to_vec(),
            Err(e) => {
                panic!("Error getting default gateway:{}", e);
            }
        }
    };

    let eth_packet = ethernet::EthernetFrame::new(
        &[0x08, 0x00],
        ip_packet.raw_bytes(),
        &dest_mac,
        &local_mac[..],
    );

    match request_and_response(eth_packet).await {
        Ok((response, roundtrip)) => match ethernet::EthernetFrame::try_from(&response[..]) {
            Ok(eth_frame) => {
                let ipv4_packet = ipv4::Ipv4::try_from(eth_frame.payload).unwrap();
                Ok((ipv4_packet,roundtrip))
            }
            Err(e) => {
                println!("{e}");
                Err(e)
            }
        },
        Err(e) => {
            println!("{e}");
            Err(e)
        }
    }
}

pub async fn request_and_response<'a>(
    ethernet_frame: ethernet::EthernetFrame<'a>,
) -> Result<(Vec<u8>, u128), &'static str> {
    let filter = match *ethernet_frame.ether_type {
        [0x08, 0x06] => {
            format!(
                "(arp[6:2] = 2) and ether dst {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                ethernet_frame.source_mac[0],
                ethernet_frame.source_mac[1],
                ethernet_frame.source_mac[2],
                ethernet_frame.source_mac[3],
                ethernet_frame.source_mac[4],
                ethernet_frame.source_mac[5]
            )
        }
        [0x08, 0x00] => {
            let ipv4_packet = ipv4::Ipv4::try_from(ethernet_frame.payload).unwrap();
            format!(
                "icmp and src host {}.{}.{}.{} and dst host {}.{}.{}.{}",
                ipv4_packet.dest_address().unwrap()[0],
                ipv4_packet.dest_address().unwrap()[1],
                ipv4_packet.dest_address().unwrap()[2],
                ipv4_packet.dest_address().unwrap()[3],
                ipv4_packet.source_address().unwrap()[0],
                ipv4_packet.source_address().unwrap()[1],
                ipv4_packet.source_address().unwrap()[2],
                ipv4_packet.source_address().unwrap()[3],
            )
        }
        _ => {
            panic!("unrecognized eth_type");
        }
    };

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
        //start a timer
        let now = Instant::now();
        loop {
            //check timer
            let elapsed_time = now.elapsed();
            if elapsed_time.as_millis() > 1000 {
                tx.send(Err("Destination host didn't respond within 1 second."));
                break;
            }

            let cap = Arc::clone(&cap);
            let mut cap = cap.lock().unwrap();
            match cap.next() {
                Ok(eth_frame) => {
                    println!("Captured a frame!");
                    tx.send(Ok(eth_frame.data.to_vec()));
                    break;
                }
                Err(_) => {
                    //No packet on the wire. Drop mutex lock and loop
                }
            };
        }
    });

    //send the packet
    let now: Instant = match cap2.lock().unwrap().sendpacket(&ethernet_frame.raw_bytes[..]) {
        Ok(()) => {
            println!("Packet sent ********************************************");
            Instant::now()
        },
        Err(e) => {panic!("Error occurred sending packet: {}",e);}
    };

    //await the reply from the channel
    match rx.await {
        Ok(v) => {
            let elapsed_time = now.elapsed().as_millis();
            match v {
                Ok(eth_packet) => Ok((eth_packet, elapsed_time)),
                Err(e) => Err(e),
            }
        }
        Err(_) => Err("Something bad happened"),
    }
}

pub fn get_local_mac_ip() -> (Vec<u8>, net::Ipv4Addr) {
    let handle = &Device::list().unwrap()[0];
    let ip_address: net::Ipv4Addr = if let net::IpAddr::V4(ip_addr) = handle.addresses[0].addr {
        ip_addr
    } else {
        panic!();
    };

    let file_path = format!("{}{}{}", SYSFS_PATH, handle.name, SYSFS_FILENAME);

    let mut file = File::open(file_path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mac: Vec<u8> = contents
        .strip_suffix('\n')
        .unwrap()
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect();

    (mac, ip_address)
}

//For use in tests. Retreives bytes from a local file captured from wireshark
pub fn get_wireshark_bytes(file_name: &str) -> Vec<u8> {
    let file = File::open(file_name).unwrap();
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents).unwrap();
    contents.pop();
    contents
        .split(',')
        .map(|v| v.trim_start_matches("0x"))
        .map(|v| u8::from_str_radix(v, 16).unwrap())
        .collect()
}



#[cfg(test)]
mod tests {

    use super::get_local_mac_ip;
    use super::*;
    use std::net;

    #[test]
    fn returns_correct_ip_and_mac_for_default_device() {
        let correct_ip: net::Ipv4Addr = net::Ipv4Addr::new(192, 168, 100, 16);
        let correct_mac: [u8; 6] = super::get_wireshark_bytes("test_source_mac.txt")
            .try_into()
            .unwrap();

        let (mac, ip_addr) = get_local_mac_ip();

        assert_eq!(correct_ip, ip_addr);
        assert_eq!(&correct_mac, &mac[..]);
    }
}
