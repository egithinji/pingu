use pcap;

pub fn get_arp_reply() -> Result<Vec<u8>, pcap::Error> {
    let mut cap = pcap::Capture::from_device("enp2s0") //need to get device name and mac address
                                                       //from system and pass this here.
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // filter for arp replies to this host and from a particular host.
    // need to use mac address retrieved from file.
    cap.filter(
        "(arp[6:2] = 2) and ether dst 04:92:26:19:4e:4f and not ether src e0:cc:7a:34:3f:a3",
        true,
    )
    .unwrap();

    match cap.next() {
        Ok(packet) => {
            return Ok(packet.data.to_vec());
        }

        Err(e) => {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{arp, senders, ethernet};
    use std::{thread, time};

    #[tokio::test]
    pub async fn get_successful_arp_reply_works() {
        let source_mac = [0x04, 0x92, 0x26, 0x19, 0x4e, 0x4f];
        let arp_request = arp::ArpRequest::new(source_mac, [192, 168, 100, 16], [192, 168, 100, 97]);

        //start listening asynchronously for arp reply

        println!("Starting to listen...");

        let handle = tokio::spawn(async { super::get_arp_reply() });

        //let hundred_millis = time::Duration::from_millis(100);
        //thread::sleep(hundred_millis);
        //send arp request
        match senders::raw_send(arp_request) {
            Ok(()) => {
                println!("Packet sent successfully.");
            }
            Err(e) => {
                println!("Error sending packet to socket: {}", e);
            }
        };

        //await async listener

        let out = handle.await.unwrap().unwrap();

        /*match out {
            Ok(packet) => println!("We received a packet!: {:?}", packet),
            Err(e) => println!("We got an error: {:?}", e),
        }*/
        
        let ethernet_packet = ethernet::EthernetFrame::try_from(&out[..]).unwrap();


        assert_eq!(&source_mac, ethernet_packet.dest_mac);
    }
}
