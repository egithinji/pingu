use pingu::arp;
use pingu::ipv4;
use pingu::packets::IcmpRequest;
use pingu::receivers;
use pingu::senders;
use pingu::senders::{Packet, PacketType};

fn main() {
    /*
    let icmp_request = IcmpRequest::new([192, 168, 100, 16], [192, 168, 100, 97]);

    let source_mac = [0x04, 0x92, 0x26, 0x19, 0x4e, 0x4f];
    //let arp_request = arp::ArpRequest::new(source_mac,[192,168,100,16],[192,168,100,1]);


    match senders::raw_send(icmp_request) {
        Ok(()) => {
            println!("Packet sent successfully.")
        }
        Err(e) => {
            println!("Error sending packet to socket: {}", e);
        }
    }*/

    /*match receivers::get_arp_reply() {
        Ok(packet) => println!("Got packet! {:?}",packet),
        Err(e) => println!("Error: {:?}",e)
    }*/

    let icmp_packet = IcmpRequest::new();
    let ipv4_packet = ipv4::Ipv4::new(
        [192, 168, 100, 16],
        [192, 168, 100, 97],
        icmp_packet.raw_bytes().clone(),
        PacketType::IcmpRequest,
    );

    match senders::raw_send(ipv4_packet) {
        Ok(()) => {
            println!("Packet sent successfully.")
        }
        Err(e) => {
            println!("Error sending packet to socket: {}", e);
        }
    }
}
