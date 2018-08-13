use std::fmt;
use std::rc::Rc;
use std::cell::RefCell;

use super::types::*;
use super::traffic_stats::TrafficStats;
use super::generic_hash::LifetimeItem;
use ndpi::Flow as NdpiFlow;
use ndpi::NdpiProtocol;

use super::host::Host;

pub struct Flow<> {
  pub l4proto: L4Proto,
  pub saddr: Rc<RefCell<Host>>,
  pub daddr: Rc<RefCell<Host>>,
  pub sport: u16,
  pub dport: u16,
  pub stats: TrafficStats,
  pub ndpi_flow: NdpiFlow,
  pub protocol: NdpiProtocol,
  detection_completed: bool,
}

impl Flow {
  pub fn new(tuple: PacketTuple, shost: &Rc<RefCell<Host>>, dhost: &Rc<RefCell<Host>>) -> Flow {
    return Flow {
      saddr: shost.clone(),
      daddr: dhost.clone(),
      sport: tuple.sport,
      dport: tuple.dport,
      l4proto: tuple.proto.into(),
      stats: Default::default(),
      ndpi_flow: NdpiFlow::new(),
      protocol: Default::default(),
      detection_completed: false,
    };
  }

  pub fn just_created(&self) -> bool {
    return self.stats.last_seen == Default::default();
  }

  pub fn get_direction(&self, tuple: PacketTuple) -> PacketDir {
    if tuple.sport == self.sport { PacketDir::Src2Dst } else { PacketDir::Dst2Src }
  }

  /* set protocol */
  pub fn set_protocol(&mut self, proto: NdpiProtocol) {
    self.protocol = proto;

    if self.protocol.app_protocol != Default::default() {
      self.detection_completed = true;
    }
  }

  /* set protocol and abort detection */
  pub fn set_detected_protocol(&mut self, proto: NdpiProtocol) {
    self.protocol = proto;
    self.detection_completed = true;
  }

  pub fn is_detection_completed(&self) -> bool {
    self.detection_completed
  }
}

impl LifetimeItem for Flow {
  fn get_last_seen(&self) -> Timeval { self.stats.last_seen }
}

impl fmt::Debug for Flow {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Flow[{:?}][{:?}:{} -> {:?}:{}]", self.l4proto, self.saddr.borrow(),
      self.sport, self.daddr.borrow(), self.dport)
  }
}
