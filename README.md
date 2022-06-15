# pingu
Pingu is an implementation of the [ ping](https://en.wikipedia.org/wiki/Ping_(networking_utility)) network utility written in Rust. It satisfies pages 14 and 15 of [RFC 792](https://datatracker.ietf.org/doc/html/rfc792).

## Why
No, it doesn't aim or claim to be a **_blazingly fast_** version of ping. It's a learning project to help me better understand Datalink and Network layer protocols, and practice writing Rust code. In particular I want to learn how to:

* Construct valid Ethernet, Ipv4 and Icmp packets
* Implement Arp logic
* Implement Icmp logic

## How
Since it's a learning project, I'm trying to write as much as possible on my own. However I am using the following dependencies:

| Crate | Reason |
| ------|--------|
| [pcap](https://github.com/rust-pcap/pcap) | For sending/receiving raw packets to/from the network device. This way I don't have to deal with system calls and instead focus on packet construction and logic |
| [crc32fast](https://github.com/srijs/rust-crc32fast) | For quickly generating ethernet frame check sequences |
| [default-net](https://github.com/shellrow/default-net) | For retreiving local mac address and default gateway |


## Contributions
Learning together is more fun so contributions/feedback/ideas are welcome!

## Todo

* [ ] Write integration tests
* [ ] Update unit tests
* [ ] Implement timeouts for unreachable hosts
* [ ] Add documentation
* [ ] Send and receive multiple Icmp requests/responses
* [ ] Add DNS support


