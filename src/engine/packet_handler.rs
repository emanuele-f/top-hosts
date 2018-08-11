use etherparse::{SlicedPacket,LinkSlice,InternetSlice,TransportSlice};

use pcap::PacketHeader;

use super::generic_hash::GenericHash;
use super::flow::Flow;
use super::host::Host;
use super::types::*;

const FLOW_IDLE_TIMEOUT_SEC: i64 = 60;
const HOST_IDLE_TIMEOUT_SEC: i64 = 300;

pub struct PacketHandler {
  flows: GenericHash<PacketTuple, Flow>,
  hosts: GenericHash<u32, Host>,
}

impl PacketHandler {
  pub fn new() -> PacketHandler {
    return PacketHandler {
      flows: GenericHash::new(FLOW_IDLE_TIMEOUT_SEC),
      hosts: GenericHash::new(HOST_IDLE_TIMEOUT_SEC),
    };
  }

  fn parse_tuple(packet: &[u8]) -> Option<(PacketTuple, MacAddress, MacAddress)> {
    let mut tuple: PacketTuple = Default::default();
    let mut srcmac: [u8; 6] = Default::default();
    let mut dstmac: [u8; 6] = Default::default();

    match SlicedPacket::from_ethernet(packet) {
      Err(value) => println!("Err {:?}", value),
      Ok(value) => {
        match value.link {
          Some(linkslice) => {
            match linkslice {
              LinkSlice::Ethernet2(ethlinkslice) => {
                let ethlink = ethlinkslice.to_header();
                srcmac = ethlink.source;
                dstmac = ethlink.destination;

                //println!("{} -> {} [{:04x}]",
                  //MacAddress::new(ethlink.source).to_hex_string(),
                  //MacAddress::new(ethlink.destination).to_hex_string(),
                  //ethlink.ether_type);
              }
            }
          },
          None => (),
        }

        match value.ip {
          Some(ipslice) => {
            match ipslice {
              InternetSlice::Ipv4(ipv4slice) => {
                let ipv4hdr = ipv4slice.to_header();
                let src = ipv4hdr.source;
                let dst = ipv4hdr.destination;
                let srvip = Ipv4Addr::new(src[0], src[1], src[2], src[3]);
                let dstip = Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]);

                tuple.saddr = srvip.into();
                tuple.daddr = dstip.into();
                tuple.proto = ipv4hdr.protocol;
              },
              InternetSlice::Ipv6(_ipv6slice, _extheader) => {
                // TODO
              },
            }
          },
          None => (),
        }

        match value.transport {
          Some(trpslice) => {
            let sport;
            let dport;

            match trpslice {
              TransportSlice::Tcp(tcpslice) => {
                let tcphdr = tcpslice.to_header();
                sport = tcphdr.source_port;
                dport = tcphdr.destination_port;
              },
              TransportSlice::Udp(udpslice) => {
                let udphdr = udpslice.to_header();
                sport = udphdr.source_port;
                dport = udphdr.destination_port;
              },
            }

            if (sport != 0) && (dport != 0) {
              tuple.sport = sport;
              tuple.dport = dport;
            }
          },
          None => (),
        }
      }
    }

    if tuple.ok() {
      return Some((tuple, MacAddress::new(srcmac), MacAddress::new(dstmac)));
    }

    None
  }

  pub fn process_packet(&mut self, header: &PacketHeader, packet: &[u8]) {
    match PacketHandler::parse_tuple(packet) {
      Some((tuple, srcmac, dstmac)) => {
        let when = header.ts.into();

        let srchost = self.hosts.or_insert(tuple.saddr, || Host::new(tuple.saddr.into(), srcmac));
        let dsthost = self.hosts.or_insert(tuple.daddr, || Host::new(tuple.daddr.into(), dstmac));
        let flow = self.flows.or_insert(tuple, || Flow::new(tuple, &srchost, &dsthost));

        if flow.borrow().just_created() {
          srchost.borrow_mut().mac = srcmac;
          dsthost.borrow_mut().mac = dstmac;
        }

        let dir = flow.borrow().get_direction(tuple);
        flow.borrow_mut().stats.account_packet(when, dir, header.len);
        srchost.borrow_mut().stats.account_packet(when, dir, header.len);
        dsthost.borrow_mut().stats.account_packet(when, dir, header.len);

        println!("{:?} ({} packets, {} bytes)", flow, flow.borrow().stats.packets(), flow.borrow().stats.bytes());
      },
      None => ()
    }
  }

  pub fn purge_idle(&mut self, now: &SystemTime) {
    debug!("purge_idle");

    self.flows.purge_idle(now);
    self.hosts.purge_idle(now);
  }
}
