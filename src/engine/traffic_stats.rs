use super::types::*;

#[derive(Debug, Default, Clone)]
pub struct TrafficStats {
  pub last_seen: Timeval,
  pub src2dst_pkts: u32,
  pub dst2src_pkts: u32,
  pub src2dst_bytes: u64,
  pub dst2src_bytes: u64,

  pub last_update: Timeval,
  pub last_bytes: u64,
  pub throughput: f64,
}

impl TrafficStats {
  pub fn account_packet(&mut self, when: Timeval, dir: PacketDir, bytes: u32) {
    if self.last_update == Default::default() {
      self.last_update = when;
    }

    match dir {
      PacketDir::Src2Dst => {
        self.src2dst_pkts += 1;
        self.src2dst_bytes += bytes as u64;
      }, PacketDir::Dst2Src => {
        self.dst2src_pkts += 1;
        self.dst2src_bytes += bytes as u64;
      }
    }

    self.last_seen = when;
  }

  pub fn update(&mut self, when: Timeval) {
    let diff_bytes = self.bytes() - self.last_bytes;
    self.throughput = (diff_bytes as f64) / (when - self.last_update);

    self.last_bytes = self.bytes();
    self.last_update = when;
  }

  pub fn packets(&self) -> u32 {
    self.src2dst_pkts + self.dst2src_pkts
  }

  pub fn bytes(&self) -> u64 {
    self.src2dst_bytes + self.dst2src_bytes
  }
}
