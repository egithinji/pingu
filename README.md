# pingu
Pingu is an implementation of the [ ping](https://en.wikipedia.org/wiki/Ping_(networking_utility)) network utility written in Rust. It aims to satisfy pages 14 and 15 of [RFC 792](https://datatracker.ietf.org/doc/html/rfc792).

## Screenshot
![Screenshot](docs/images/pingu_screenshot.png)

## Why
It's a learning project to help me better understand Datalink and Network layer protocols, and practice writing Rust code. In particular I want to learn how to:

* Construct valid Ethernet, Ipv4 and Icmp packets
* Implement Arp logic
* Implement Icmp logic

## How
Since it's a learning project, I'm trying to write as much as possible on my own. However I am using the following dependencies:

| Crate | Reason |
| ------|--------|
| [pcap](https://github.com/rust-pcap/pcap) | For sending/receiving raw packets to/from the network device. This way I don't have to deal with system calls and instead focus on packet construction and logic |
| [crc32fast](https://github.com/srijs/rust-crc32fast) | For quickly generating ethernet frame check sequences |
| [default-net](https://github.com/shellrow/default-net) | For retreiving default gateway |

## Installation (Debian based Linux)
* [Install rust](https://doc.rust-lang.org/book/ch01-01-installation.html)
* Install libpcap-dev
```
sudo apt update
sudo apt install libpcap-dev
```
* Clone this repo
* Build:
```
cargo build --release
```
* Set the following capabilities:
```
sudo setcap cap_net_raw,cap_net_admin=eip path/to/pingu/target/release
```
* Add binary to PATH. Add the following to your ~/.bashrc:
```
export PATH=path/to/pingu/target/release

```
* Restart terminal, then Run as follows:
```
pingu 8.8.8.8
```

## Contributions
Learning together is fun! So please feel free to contribute code/feedback/ideas.

## Todo

* [ ] Write integration tests
* [ ] Fix unit tests
* [x] Implement timeouts for unreachable hosts
* [ ] Move get_mac_of_target() fn to utilities.rs and inline it
* [ ] Add documentation


