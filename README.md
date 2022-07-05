# pingu
Pingu is a playground for implementing network protocols and utilities in Rust. For any utility, the aim is to successfully communicate with a real world host. For example it contains an implementation of [ ping](https://en.wikipedia.org/wiki/Ping_(networking_utility)), that aims to satisfy pages 14 and 15 of [RFC 792](https://datatracker.ietf.org/doc/html/rfc792).

## Screenshot
![Screenshot](docs/images/pingu_screenshot.png)

## Why
The idea is to learn-by-doing with regards to network protocols and writing Rust code.

## How
When there is a need to send/receive raw ethernet packets via the network device (e.g. in the implementation of [ ping](https://en.wikipedia.org/wiki/Ping_(networking_utility))), [pcap](https://github.com/rust-pcap/pcap) is used. Otherwise the networking primitives in [the standard library](https://doc.rust-lang.org/std/net/index.html) are used. 

## Installation (Debian based Linux)
* [Install nightly rust](https://doc.rust-lang.org/book/appendix-07-nightly-rust.html#rustup-and-the-role-of-rust-nightly)
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
* Restart your terminal

## Running

* Ping utility
```
pingu 8.8.8.8
```

## Contributions
Contributions of code/feedback/ideas to the playground are very welcome. E.g. if you want to practice implementing a network tool/protocol in Rust.

## Todo

* [ ] Write integration tests
* [ ] Fix unit tests
* [x] Implement timeouts for unreachable hosts
* [ ] Move get_mac_of_target() fn to utilities.rs and inline it
* [ ] Add documentation
