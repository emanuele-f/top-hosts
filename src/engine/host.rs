use std::fmt;
use super::types::*;
use super::traffic_stats::TrafficStats;
use super::generic_hash::LifetimeItem;

pub struct Host {
  pub ip: Ipv4Addr,
  pub mac: MacAddress,
  pub stats: TrafficStats,
}

impl Host {
  pub fn new(ip: Ipv4Addr, mac: MacAddress) -> Host {
    Host {
      ip: ip,
      mac: mac,
      stats: Default::default(),
    }
  }
}

impl LifetimeItem for Host {
  fn get_last_seen(&self) -> Timeval { self.stats.last_seen }
}

impl fmt::Debug for Host {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Host[{}][{}]", self.ip, self.mac)
  }
}
