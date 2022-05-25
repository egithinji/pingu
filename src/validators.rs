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
            },
            Err(_) => {
                return Err(Ipv4ValidationError::IncorrectRange);
            }
        }
    }

    Ok(())

}

#[cfg(test)]
mod tests {

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
}
