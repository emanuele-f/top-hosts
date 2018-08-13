//#![feature(nll)]

extern crate libc;
extern crate eui48;
extern crate pcap;
extern crate ndpi;
extern crate etherparse;
extern crate simple_logger;
extern crate termion;
extern crate tui;

#[macro_use] extern crate log;

use pcap::Device;
use pcap::Capture;

mod engine;
mod ui;

use engine::types::*;
use engine::packet_handler::*;
use ui::*;
use termion::input::TermRead;
use log::{LevelFilter, set_max_level};
use std::io::Read;
use termion::async_stdin;

const SNAPLEN: i32 = 0;
const PROMISC: bool = true;
const PACKET_TIMEOUT_MS: i32 = 10;
const PURGE_TIMEOUT_SEC: u64 = 3;
const REDRAW_TIEMOUT_SEC: u64 = 3;

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
    .immediate_mode(true)
    .open().unwrap();

  // to set maximum log level
  set_max_level(LevelFilter::Info);

  let mut gui = Ui::new();
  let mut handler = PacketHandler::new();
  let mut last_purge = SystemTime::now();
  let mut last_redraw = SystemTime::now();
  let purge_timeput = Duration::new(PURGE_TIMEOUT_SEC, 0);
  let redraw_timeout = Duration::new(REDRAW_TIEMOUT_SEC, 0);
  let mut first_redraw = true;
  let mut running = true;
  let mut stdin = async_stdin().bytes();

  while running {
    if let Ok(packet) = cap.next() {
      handler.process_packet(packet.header, packet.data);
    }

    let now = SystemTime::now();

    if now.duration_since(last_purge).unwrap() >= purge_timeput {
      handler.purge_idle(&now);
      last_purge = now;
    } else if first_redraw || now.duration_since(last_redraw).unwrap() >= redraw_timeout {
      gui.draw().unwrap();
      last_redraw = now;
      first_redraw = false;
    } else {
      while let Some(Ok(c)) = stdin.next() {
        match c {
          b'q' => { running = false; break},
          _ => (),
        }
      }
    }
  }
}
