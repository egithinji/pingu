use crate::ethernet;
use crate::icmp;
use crate::ipv4;
use crate::senders::Packet;
use pcap;
use pcap::{Active, Capture};
use std::sync::{Arc, Mutex};

pub fn get_one_reply(cap: Arc<Mutex<Capture<Active>>>) -> Result<Vec<u8>, pcap::Error> {

    let mut cap = cap.lock().unwrap();
    println!("Listening...");
    match cap.next() {
        Ok(packet) => {
            println!("Received a packet!");
            return Ok(packet.data.to_vec().clone());
        }

        Err(e) => {
            println!("No packet found, returning...");
            return Err(e);
        }
    }
}

pub fn print_reply(bytes: &[u8]) -> String {
    let eth_packet = ethernet::EthernetFrame::try_from(bytes).unwrap();
    let ipv4_packet = ipv4::Ipv4::try_from(eth_packet.payload).unwrap();
    let icmp = icmp::IcmpRequest::try_from(&ipv4_packet.payload[..]).unwrap();

    format!("{:?}", ipv4_packet.source_address)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{arp, ethernet, senders};
    use pcap::Device;
    use std::{thread, time};

    #[tokio::test]
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
    }
}
