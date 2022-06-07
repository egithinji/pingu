use pcap::Device;
use std::net;
use std::fs::File;
use std::io::prelude::*;

const SYSFS_PATH: &'static str = "/sys/class/net/";
const SYSFS_FILENAME: &'static str = "/address";

pub fn get_local_mac_ip() -> (Vec<u8>, net::Ipv4Addr) {
    let mut ip_address: net::Ipv4Addr;

    let mut handle = &Device::list().unwrap()[0];
    if let net::IpAddr::V4(ip_addr) = handle.addresses[0].addr {
        ip_address = ip_addr;
    } else {
        panic!();
    }

    let file_path = format!("{}{}{}", SYSFS_PATH, handle.name, SYSFS_FILENAME);

    let mut file = File::open(file_path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mac: Vec<u8> = contents
        .strip_suffix("\n")
        .unwrap()
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect();

    (mac, ip_address)
}

#[derive(Debug, PartialEq)]
pub enum Ipv4ValidationError {
    TotalOctetsIncorrect,
    IncorrectRange,
    InvalidCharacter,
}

pub fn ipv4(address: &str) -> Result<(), Ipv4ValidationError> {
    for char in address.chars() {
        if !(char.is_numeric() || char == '.') {
            return Err(Ipv4ValidationError::InvalidCharacter);
        }
    }

    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 {
        return Err(Ipv4ValidationError::TotalOctetsIncorrect);
    }

    for octet in octets {
        match octet.parse::<u8>() {
            Ok(_) => {
                //
            }
            Err(_) => {
                return Err(Ipv4ValidationError::IncorrectRange);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::get_local_mac_ip;
    use super::Ipv4ValidationError;
    use crate::validators;

    #[test]
    fn ipv4address_contains_only_digits_and_periods() {
        let ip_addr: &str = "192.abc.1.0";
        let ip_addr2: &str = "192,168,1,0";
        let ip_addr3: &str = "192.168.1.-1";

        assert_eq!(
            validators::ipv4(ip_addr),
            Err(Ipv4ValidationError::InvalidCharacter)
        );

        assert_eq!(
            validators::ipv4(ip_addr2),
            Err(Ipv4ValidationError::InvalidCharacter)
        );

        assert_eq!(
            validators::ipv4(ip_addr3),
            Err(Ipv4ValidationError::InvalidCharacter)
        );
    }

    #[test]
    fn ipv4address_must_have_four_octets() {
        let ip_addr: &str = "192.168.1";
        let ip_addr2: &str = "";
        assert_eq!(
            validators::ipv4(ip_addr),
            Err(Ipv4ValidationError::TotalOctetsIncorrect)
        );
        assert_eq!(
            validators::ipv4(ip_addr2),
            Err(Ipv4ValidationError::TotalOctetsIncorrect)
        );
    }

    #[test]
    fn ipv4address_each_octet_within_correct_range() {
        let ip_addr: &str = "300.168.1.0";
        let ip_addr2: &str = "1922.168.1.0";

        assert_eq!(
            validators::ipv4(ip_addr),
            Err(Ipv4ValidationError::IncorrectRange)
        );
        assert_eq!(
            validators::ipv4(ip_addr2),
            Err(Ipv4ValidationError::IncorrectRange)
        );
    }

    #[test]
    fn valid_ipv4address_passes() {
        let ip_addr: &str = "192.168.100.100";
        assert!(validators::ipv4(ip_addr).is_ok());
    }

    #[test]
    #[ignore]
    fn returns_correct_ip_and_mac_for_default_device() {
        let correct_ip: net::Ipv4Addr = net::Ipv4Addr::new(192, 168, 100, 16);
        let correct_mac: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; //replace with real mac
                                                                         //when testing

        let (mac, ip_addr) = get_local_mac_ip();

        assert_eq!(correct_ip, ip_addr);
        assert_eq!(&correct_mac, &mac[..]);
    }
}
