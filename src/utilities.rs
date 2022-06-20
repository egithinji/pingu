use crate::arp;
use crate::ethernet;
use crate::icmp;
use crate::icmp::IcmpRequest;
use crate::ipv4;
use crate::senders::{raw_send, Packet, PacketType};
use crate::utilities;
use pcap;
use pcap::Device;
use pcap::{Active, Capture};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const SYSFS_PATH: &str = "/sys/class/net/";
const SYSFS_FILENAME: &str = "/address";

pub async fn single_pingu(dest_ip: net::Ipv4Addr) -> Result<ipv4::Ipv4, &'static str> {
    let (local_mac, local_ip) = utilities::get_local_mac_ip();

    let icmp_packet = IcmpRequest::new();
    let ipv4_packet = ipv4::Ipv4::new(
        local_ip.octets(),
        dest_ip.octets(),
        icmp_packet.raw_bytes().clone(),
        PacketType::IcmpRequest,
    );

    let dest_mac: Vec<u8> = if dest_ip.is_private() {
        println!("dest ip is private, get mac of target...");
        match arp::get_mac_of_target(&dest_ip.octets(), &local_mac, &local_ip.octets()).await {
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
        ipv4_packet.raw_bytes(),
        &dest_mac,
        &local_mac[..],
    );

    let (response, roundtrip) = request_and_response(eth_packet).await.unwrap();

    match ethernet::EthernetFrame::try_from(&response[..]) {
        Ok(eth_packet) => {
            println!(
                "Received packet from {}. Round-trip time: {}",
                print_reply(&eth_packet.raw_bytes[..]),
                roundtrip
            );
            let ipv4_packet = ipv4::Ipv4::try_from(eth_packet.payload).unwrap();
            Ok(ipv4_packet)
        }
        Err(e) => {
            println!("{e}");
            Err(e)
        }
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

fn print_reply(bytes: &[u8]) -> String {
    let eth_packet = ethernet::EthernetFrame::try_from(bytes).unwrap();
    let ipv4_packet = ipv4::Ipv4::try_from(eth_packet.payload).unwrap();

    format!("{:?}", ipv4_packet.source_address)
}

pub async fn request_and_response<'a>(
    ethernet_packet: ethernet::EthernetFrame<'a>,
) -> Result<(Vec<u8>, u128), &'static str> {
    let filter = match *ethernet_packet.ether_type {
        [0x08, 0x06] => {
            format!(
                "(arp[6:2] = 2) and ether dst {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                ethernet_packet.source_mac[0],
                ethernet_packet.source_mac[1],
                ethernet_packet.source_mac[2],
                ethernet_packet.source_mac[3],
                ethernet_packet.source_mac[4],
                ethernet_packet.source_mac[5]
            )
        }
        [0x08, 0x00] => {
            let ipv4_packet = ipv4::Ipv4::try_from(ethernet_packet.payload).unwrap();
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
                Ok(packet) => {
                    println!("Received a packet!");
                    tx.send(Ok(packet.data.to_vec()));
                    break;
                }
                Err(_) => {
                    //No packet on the wire. Drop mutex lock and loop
                }
            };
        }
    });

    //send the packet
    let now: Instant = match raw_send(&ethernet_packet.raw_bytes[..], cap2) {
        Ok(instant) => instant,
        Err(e) => {
            panic!("Error sending packet to socket: {e}");
        }
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
    use crate::{arp, ethernet, icmp, ipv4, senders, utilities};
    use default_net;
    use pcap::Device;
    use std::net;
    use std::{thread, time};

    /*#[tokio::test]
    #[ignore]
    pub async fn get_successful_arp_reply_works() {
        let source_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let arp_request =
            arp::ArpRequest::new(&source_mac, &[192, 168, 100, 16], &[192, 168, 100, 132]);

        let handle = Device::list().unwrap().remove(0);
        let mut cap = handle.open().unwrap();

        // filter for arp replies to this host and from a particular host.
        // need to use mac address retrieved from file.
        let filter = "(arp[6:2] = 2) and ether dst 00:00:00:00:00:00"; //replace with real mac when
                                                                       //testing

        //start listening asynchronously for arp reply
        let handle = tokio::spawn(async { super::get_one_reply(&filter) });

        //send arp request
        match senders::raw_send(&arp_request.raw_bytes[..]) {
            Ok(_) => {
                println!("Packet sent successfully.");
            }
            Err(e) => {
                println!("Error sending packet to socket: {}", e);
            }
        };

        //await async listener

        let out = handle.await.unwrap().unwrap();

        let ethernet_packet = ethernet::EthernetFrame::try_from(&out[..]).unwrap();

        assert_eq!(&source_mac, ethernet_packet.dest_mac);
    }*/

    /*
    #[tokio::test]
    pub async fn external_icmp_request_receives_valid_reply() {
        let dest_ip: net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        let (local_mac, local_ip) = utilities::get_local_mac_ip();
        let default_gateway_mac = match default_net::get_default_gateway() {
            Ok(gateway) => gateway.mac_addr.octets().to_vec(),
            Err(e) => {
                panic!("Error getting default gateway:{}", e);
            }
        };

        let icmp_packet = icmp::IcmpRequest::new();
        let ipv4_packet = ipv4::Ipv4::new(
            local_ip.octets(),
            dest_ip.octets(),
            icmp_packet.raw_bytes().clone(),
            senders::PacketType::IcmpRequest,
        );
        let ethernet_packet = ethernet::EthernetFrame::new(
            &[0x08, 0x00],
            ipv4_packet.raw_bytes(),
            &default_gateway_mac,
            &local_mac,
        );

        let bytes: Vec<u8> = request_and_response(ethernet_packet).await;

        let response: ipv4::Ipv4 = ipv4::Ipv4::try_from(&bytes[..]).unwrap();

        let icmp_response = icmp::IcmpRequest::try_from(&response.payload[..]).unwrap();

        assert_eq!(ipv4_packet.source_address, response.dest_address);
        assert_eq!(ipv4_packet.dest_address, response.source_address);
        assert_eq!(ipv4_packet.payload, response.payload);
        assert_eq!(ipv4_packet.packet_type, response.packet_type);
        assert_eq!(ipv4_packet.identification, response.identification);
        assert_eq!(icmp_response.code, 1);
    }
    */

    /*
    #[tokio::test]
    pub async fn arp_broadcast_receives_valid_reply() {
        let target_ip: net::Ipv4Addr = "192.168.100.129".parse().unwrap();
        let target_ip = target_ip.octets();
        let (source_mac, source_ip) = utilities::get_local_mac_ip();

        let arp_request = arp::ArpRequest::new(&source_mac, &source_ip.octets(), &target_ip);

        let bytes: Vec<u8> = request_and_response(&arp_request).await.unwrap();

        let arp_response = arp::ArpRequest::try_from(&bytes[..]).unwrap();
        assert_eq!(arp_response.dest_address(), arp_request.source_address());
        assert_eq!(arp_response.source_address(), arp_request.dest_address());
        assert_eq!(arp_response.oper, 2);
    }
    */

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
