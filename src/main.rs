use pingu::packets::IcmpRequest;
use pingu::senders;

fn main() {
    let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);

    match senders::raw_send(icmp_request) {
        Ok(()) => {
            println!("Packet sent successfully.")
        }
        Err(e) => {
            println!("Error sending packet to socket: {}", e);
        }
    }
}
