use crate::ethernet;
use pcap::{Device, Error};

pub enum PacketType {
    IcmpRequest,
    Arp,
}

pub trait Packet {
    fn raw_bytes(&self) -> &Vec<u8>;
    fn packet_type(&self) -> PacketType;
}

pub fn raw_send(packet: impl Packet) -> Result<(), Error> {

    let (dest_mac,eth_type) = match packet.packet_type() {
        PacketType::IcmpRequest => {
            ([0xe0, 0xcc, 0x7a, 0x34, 0x3f, 0xa3], [0x08,0x00]) //temporary fix. dest_mac should be
                                                                //obtained via arp.
        },
        PacketType::Arp => {
            ([0xff,0xff,0xff,0xff,0xff,0xff,], [0x08,0x06])
        }
    };

    let source_mac = [0x04, 0x92, 0x26, 0x19, 0x4e, 0x4f]; //temporary fix. source_mac shold be
                                                           //found via file system.
    let eth_packet = ethernet::EthernetFrame::new(&eth_type, &packet.raw_bytes(), &dest_mac, &source_mac);

    let mut handle = Device::lookup().unwrap().open().unwrap();

    handle.sendpacket(&eth_packet.raw_bytes[..])
}

pub fn get_local_mac() -> String {
    unimplemented!();
}

#[cfg(test)]
mod tests {

    use super::raw_send;
    use super::get_local_mac;
    use crate::packets::IcmpRequest;

    #[test]
    fn valid_packet_sent_down_wire() {
        let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);
        let result = raw_send(icmp_request);

        assert!(result.is_ok());
    }

    #[test]
    #[ignore]
    fn local_mac_address_successfully_retrieved() {
        let local_mac = "04:92:26:19:4e:4f";
        let mac: &str = &get_local_mac();

        assert_eq!(local_mac,mac);

    }
}
