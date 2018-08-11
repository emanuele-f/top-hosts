use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;

use super::types::*;

pub struct GenericHash<K,V> {
  items: HashMap<K, Rc<RefCell<V>>>,
  idle_timeout: i64,
}

pub trait LifetimeItem {
  fn get_last_seen(&self) -> Timeval;
}

impl <K: ::std::cmp::Eq + ::std::hash::Hash,V: LifetimeItem + ::std::fmt::Debug> GenericHash<K,V> {
  pub fn new(idle_timeout: i64) -> GenericHash<K,V> {
    GenericHash {
      items: HashMap::new(),
      idle_timeout: idle_timeout,
    }
  }

  pub fn or_insert<F>(&mut self, k: K, item_builder: F) -> Rc<RefCell<V>>
    where F: Fn() -> V {

    let item = self.items.entry(k).or_insert_with(|| Rc::new(RefCell::new(item_builder()))).clone();
    item
  }

  pub fn purge_idle(&mut self, now: &SystemTime) {
    let timeout = self.idle_timeout;

    self.items.retain(|_k, v| {
      (Rc::strong_count(v) == 1) && {/* this hash is the only owner */
        let tstamp = now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let is_idle = (tstamp - v.borrow().get_last_seen().sec) < timeout;

        if is_idle {
          debug!("Idle Purge: {:?}", v.borrow());
        }

        is_idle
      }
    });
  }
}
