use pingtel::packets::IcmpRequest;
use pingtel::senders::UdpSender;

fn main() {
    let icmp_request = IcmpRequest::new([192, 168, 100, 16], [8, 8, 8, 8]);

    let udp_sender = UdpSender::new(icmp_request);

    udp_sender.send();
}
