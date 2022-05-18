use crate::packets::IcmpRequest;
use nix::errno;
use nix::sys::socket::{
    sendto, socket, AddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn,
};

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
        match sendto(self.socket, &self.buffer[..], &self.socket_address, self.msg_flags) {
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

struct rawSender {

}
