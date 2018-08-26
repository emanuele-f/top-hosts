use std::collections::HashMap;
use super::types::*;

pub struct GenericHash<K,V> {
  items: HashMap<K, ManagedPtr<V>>,
  idle_timeout: i64,
}

pub trait LifetimeItem {
  fn get_last_seen(&self) -> Timeval;
  fn get_refs(&mut self) -> &mut u32;

  fn inc_refs(&mut self) {
    (*self.get_refs()) += 1;
  }

  fn dec_refs(&mut self) {
    let refs = self.get_refs();

    if *refs > 0 {
      *refs -= 1;
    }
  }
}

impl <K: ::std::cmp::Eq + ::std::hash::Hash,V: LifetimeItem + ::std::fmt::Debug> GenericHash<K,V> {
  pub fn new(idle_timeout: i64) -> GenericHash<K,V> {
    GenericHash {
      items: HashMap::new(),
      idle_timeout: idle_timeout,
    }
  }

  pub fn or_insert<F>(&mut self, k: K, item_builder: F) -> ManagedPtr<V>
    where F: Fn() -> V {
      let item: &ManagedPtr<V> = self.items.entry(k).or_insert_with(|| ManagedPtr::new(Box::new(item_builder())));
      let ptr: ManagedPtr<V> = (*item).clone(); // duplicate ownership
      ptr
  }

  pub fn purge_idle(&mut self, now: &SystemTime) {
    let timeout = self.idle_timeout;

    self.items.retain(|_k, v| {
      ((*v.get_refs()) > 0) || {
        let tstamp = now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let idle_sec = tstamp - v.get_last_seen().sec;
        let is_idle = idle_sec > timeout;

        if is_idle {
          debug!("Purge Idle: {:?} ({} sec idle)", v, idle_sec);
          v.free();
        }

        !is_idle
      }
    });
  }
}
