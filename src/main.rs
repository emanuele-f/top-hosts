//#![feature(nll)]

extern crate libc;
extern crate eui48;
extern crate pcap;
extern crate ndpi;
extern crate etherparse;
extern crate simple_logger;

#[macro_use] extern crate log;

use pcap::Device;
use pcap::Capture;

mod engine;

use engine::types::*;
use engine::packet_handler::*;

/*
 * - DPI
 * - Hash with lifetime handler
 * - Packet header parser
 */

const SNAPLEN: i32 = 0;
const PROMISC: bool = true;
const PACKET_TIMEOUT_MS: i32 = 1000; // NOTE: not honored, immediate_mode not set
const PURGE_TIMEOUT_SEC: u64 = 3;

impl std::convert::From<u8> for L4Proto {
  fn from(proto: u8) -> L4Proto {
    match proto {
      1 => L4Proto::ICMP,
      6 => L4Proto::TCP,
      17 => L4Proto::UDP,
      _ => L4Proto::UNKNOWN,
    }
  }
}

fn main() {
  simple_logger::init().unwrap();

  let main_device = Device::lookup().unwrap();
  let mut cap = Capture::from_device(main_device).unwrap()
    .promisc(PROMISC)
    .snaplen(SNAPLEN)
    .timeout(PACKET_TIMEOUT_MS)
    .open().unwrap();

  let mut handler = PacketHandler::new();
  let mut last_purge = SystemTime::now();
  let purge_timeput = Duration::new(PURGE_TIMEOUT_SEC, 0);

  while let Ok(packet) = cap.next() {
    let now = SystemTime::now();
    handler.process_packet(packet.header, packet.data);

    if now.duration_since(last_purge).unwrap() >= purge_timeput {
      handler.purge_idle(&now);
      last_purge = now;
    }
  }
}
