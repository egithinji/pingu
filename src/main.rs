use pingu::packets::IcmpRequest;
use pingu::senders::UdpSender;
use pingu::senders;
use pingu::ethernet;

fn main() {
    //let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);

    //senders::raw_send("enp2s0".to_string(),icmp_request);


    //let udp_sender = UdpSender::new(icmp_request);

   // udp_sender.send();

    let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);

    senders::raw_send("enp2s0".to_string(),icmp_request);
    //senders::raw_send3(icmp_request);

}
