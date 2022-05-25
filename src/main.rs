use pingu::packets::IcmpRequest;
use pingu::senders;
use pingu::arp;

fn main() {
    //let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);
    
    let source_mac = [0x04, 0x92, 0x26, 0x19, 0x4e, 0x4f]; 
    let arp_request = arp::ArpRequest::new(source_mac,[192,168,100,16],[192,168,100,1]);


    match senders::raw_send(arp_request) {
        Ok(()) => {
            println!("Packet sent successfully.")
        }
        Err(e) => {
            println!("Error sending packet to socket: {}", e);
        }
    }
}
