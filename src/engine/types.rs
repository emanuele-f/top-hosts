use std::convert;
use std::ops::Sub;
use libc::timeval as libc_timeval;

pub type Duration = ::std::time::Duration;
pub type SystemTime = ::std::time::SystemTime;
pub type Ipv4Addr = ::std::net::Ipv4Addr;
pub type MacAddress = ::eui48::MacAddress;
pub type ManagedPtr<T> = super::managed_ptr::ManagedPtr<T>;
pub const UNIX_EPOCH: SystemTime = ::std::time::UNIX_EPOCH;

pub fn u32_to_ipv4(val: u32) -> Ipv4Addr {
  Ipv4Addr::new(
    (val >> 24) as u8 & 0xFF,
    (val >> 16) as u8 & 0xFF,
    (val >> 8) as u8 & 0xFF,
    (val) as u8 & 0xFF)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timeval {
  pub sec: i64,
  pub usec: i64,
}

impl convert::From<libc_timeval> for Timeval {
  fn from(val : libc_timeval) -> Timeval {
    Timeval {
      sec: val.tv_sec,
      usec: val.tv_usec,
    }
  }
}

impl convert::From<SystemTime> for Timeval {
  fn from(val : SystemTime) -> Timeval {
    let since_the_epoch = val.duration_since(UNIX_EPOCH).unwrap();

    Timeval {
      sec: since_the_epoch.as_secs() as i64,
      usec: since_the_epoch.subsec_micros() as i64,
    }
  }
}

impl Sub for Timeval {
  type Output = f64;

  fn sub(self, other: Timeval) -> f64 {
    (self.sec - other.sec) as f64 + ((self.usec - other.usec) as f64 / 1000_000_f64)
  }
}

#[derive(Clone, Copy, Debug)]
pub enum PacketDir {
  Src2Dst,
  Dst2Src
}

impl PacketDir {
  pub fn is_src2_dest(&self) -> bool {
    match self {
      PacketDir::Src2Dst => true,
      PacketDir::Dst2Src => false,
    }
  }
}

#[derive(Debug)]
pub enum L4Proto {
  TCP,
  UDP,
  ICMP,

  UNKNOWN
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct PacketTuple {
  pub proto: u8,
  pub saddr: u32,
  pub daddr: u32,
  pub sport: u16,
  pub dport: u16
}

impl PacketTuple {
  pub fn ok(&self) -> bool {
    return (self.proto != 0)
      && (self.saddr!=0) && (self.daddr != 0)
      && (self.sport != 0) && (self.dport!=0);
  }
}
