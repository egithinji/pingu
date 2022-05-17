use pingtel::IcmpRequest;
use nix::sys::socket::{sendto,socket,SockaddrIn,AddressFamily,SockType,SockFlag,MsgFlags,bind};
use nix::errno;

fn main() {
  
    let socket_address = SockaddrIn::new(8,8,8,8,8);

    let socket = socket(AddressFamily::Inet,SockType::Datagram,SockFlag::empty(),None).unwrap();

    let icmp_request = IcmpRequest::new([192,168,100,16],[8,8,8,8]);
   
    let slice = &icmp_request.entire_packet[..];
    let r = sendto(socket,slice,&socket_address,MsgFlags::empty()).unwrap() as i32;

   println!("Result: {}",errno::from_i32(r));
}
