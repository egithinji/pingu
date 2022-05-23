use crate::ethernet;
use crate::packets::IcmpRequest;
use pcap::{Device, Error};

pub fn raw_send(icmp_packet: IcmpRequest) -> Result<(), Error> {
    let dest_mac = [0xe0, 0xcc, 0x7a, 0x34, 0x3f, 0xa3];
    let source_mac = [0x04, 0x92, 0x26, 0x19, 0x4e, 0x4f];
    let eth_packet = ethernet::EthernetFrame::new(icmp_packet.entire_packet, dest_mac, source_mac);

    let mut handle = Device::lookup().unwrap().open().unwrap();

    println!("Sending {:?}", &eth_packet.raw_bytes[..]);
    println!("Sending {:?} bytes", &eth_packet.raw_bytes[..].len());

    handle.sendpacket(&eth_packet.raw_bytes[..])
}

#[cfg(test)]
mod tests {

    use super::raw_send;
    use crate::packets::IcmpRequest;

    #[test]
    fn valid_packet_sent_down_wire() {
        let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);
        let result = raw_send(icmp_request);

        assert!(result.is_ok());
    }
}
