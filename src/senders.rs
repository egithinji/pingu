use crate::packets::IcmpRequest;
use nix::errno;
use nix::sys::socket::{sendto, socket, AddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use crate::ethernet;
use libc::c_int;
use pcap::Device;
use pcap::Capture;

pub struct UdpSender {
    socket: i32,
    buffer: Vec<u8>,
    socket_address: SockaddrIn,
    msg_flags: MsgFlags,
}

impl UdpSender {
    pub fn new(icmp_packet: IcmpRequest) -> Self {
        let socket_address = SockaddrIn::new(
            icmp_packet.dest_address[0],
            icmp_packet.dest_address[1],
            icmp_packet.dest_address[2],
            icmp_packet.dest_address[3],
            8,
        );

        let new_socket = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .unwrap();

        let slice = &icmp_packet.entire_packet[..];

        UdpSender {
            socket: new_socket,
            buffer: icmp_packet.entire_packet,
            socket_address,
            msg_flags: MsgFlags::empty(),
        }
    }

    pub fn send(self) {
        match sendto(
            self.socket,
            &self.buffer[..],
            &self.socket_address,
            self.msg_flags,
        ) {
            Ok(n) => {
                println!("Sent {} bytes down the wire.", n);
            }
            Err(n) => {
                println!(
                    "Error sending packet to socket: {}",
                    errno::from_i32(n as i32)
                );
            }
        }
    }
}

pub fn raw_send(if_name: String, icmp_packet: IcmpRequest) {
    let interface_name = if_name;
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let dest_mac = [0xe0,0xcc,0x7a,0x34,0x3f,0xa3];
    let source_mac = [0x04,0x92,0x26,0x19,0x4e,0x4f];

    //create a new ethernet packet
    let eth_frame = crate::ethernet::EthernetFrame::new(icmp_packet.entire_packet,dest_mac,source_mac);

    println!("Sending the following to the wire:{:?}",&eth_frame.raw_bytes[..]);

    println!("Total length: {}",&eth_frame.raw_bytes.len());

    match tx.send_to(&eth_frame.raw_bytes[..], None).unwrap() {
        Ok(()) => {
            println!("Packet sent successfully.");
        }
        Err(e) => {
            println!("Failure sending packet: {}", e);
        }
    }
}

pub fn raw_send2(icmp_packet: IcmpRequest) {
    
    //create a socket
    let my_socket = socket( 
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::empty(),
        None,
    ).unwrap();

    let socket_address = SockaddrIn::new(
            icmp_packet.dest_address[0],
            icmp_packet.dest_address[1],
            icmp_packet.dest_address[2],
            icmp_packet.dest_address[3],
            8,
        );
   
    let dest_mac = [0xe0,0xcc,0x7a,0x34,0x3f,0xa3];
    let source_mac = [0x04,0x92,0x26,0x19,0x4e,0x4f];

    let eth_packet = ethernet::EthernetFrame::new(icmp_packet.entire_packet, dest_mac, source_mac);

    match sendto(
            my_socket,
            &eth_packet.raw_bytes[..],
            &socket_address,
            MsgFlags::empty(),
        ) {
            Ok(n) => {
                println!("Sent {} bytes down the wire.", n);
            }
            Err(n) => {
                println!(
                    "Error sending packet to socket: {}",
                    errno::from_i32(n as i32)
                );
            }
        }


}

pub fn raw_send3(icmp_packet: IcmpRequest) {

    let dest_mac = [0xe0,0xcc,0x7a,0x34,0x3f,0xa3];
    let source_mac = [0x04u8.to_be(),0x92u8.to_be(),0x26u8.to_be(),0x19u8.to_be(),0x4eu8.to_be(),0x4fu8.to_be()];
    let eth_packet = ethernet::EthernetFrame::new(icmp_packet.entire_packet, dest_mac, source_mac);

    let mut handle = Device::lookup().unwrap().open().unwrap();

    println!("Sending {:?}", &eth_packet.raw_bytes[..]);
    println!("Sending {:?} bytes", &eth_packet.raw_bytes[..].len());

    match handle.sendpacket(&eth_packet.raw_bytes[..]) {
        Ok(()) => {
            println!("Packet sent successfully.")
        },
        Err(e) => {
            println!("Error sending packet to socket: {}",e);
        }
    }


}
