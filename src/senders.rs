use crate::packets::IcmpRequest;
use crate::ethernet;
use pcap::Device;

pub fn raw_send(icmp_packet: IcmpRequest) {

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
