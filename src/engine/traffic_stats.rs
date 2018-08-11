use super::types::*;

#[derive(Debug, Default)]
pub struct TrafficStats {
  pub last_seen: Timeval,
  pub src2dst_pkts: u32,
  pub dst2src_pkts: u32,
  pub src2dst_bytes: u64,
  pub dst2src_bytes: u64,
}

impl TrafficStats {
  pub fn account_packet(&mut self, when: Timeval, dir: PacketDir, bytes: u32) {
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

  pub fn packets(&self) -> u32 {
    self.src2dst_pkts + self.dst2src_pkts
  }

  pub fn bytes(&self) -> u64 {
    self.src2dst_bytes + self.dst2src_bytes
  }
}
