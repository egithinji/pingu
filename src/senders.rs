use pcap::{Active, Capture, Error};
use std::time::Instant;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq)]
pub enum PacketType {
    IcmpRequest,
    Arp,
    Ethernet,
}

pub trait Packet {
    fn raw_bytes(&self) -> &Vec<u8>;
    fn packet_type(&self) -> PacketType;
    fn dest_address(&self) -> Option<Vec<u8>>;
    fn source_address(&self) -> Option<Vec<u8>>;
}

pub fn raw_send(bytes: &[u8], cap: Arc<Mutex<Capture<Active>>>) -> Result<Instant, Error> {
    let mut cap = cap.lock().unwrap();
    match cap.sendpacket(bytes) {
        Ok(()) => {
            println!("Packet sent ********************************************");
            Ok(Instant::now())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    
}
