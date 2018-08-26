use std::fmt;
use std::ops::{Deref, DerefMut};
use std::clone::Clone;

// A wrapper around raw pointers with automatic dereference

pub struct ManagedPtr<T:?Sized> {
  ptr: *mut T
}

impl <T:?Sized> ManagedPtr<T> {
  pub fn new(item: Box<T>) -> ManagedPtr<T> {
    ManagedPtr{ ptr: Box::into_raw(item) }
  }

  pub fn free(&mut self) {
    unsafe { drop(Box::from_raw(self.ptr)) }
  }
}

impl<T: ?Sized> Deref for ManagedPtr<T> {
  type Target = T;

  fn deref(&self) -> &T {
    unsafe { &*self.ptr }
  }
}

impl<T: ?Sized> DerefMut for ManagedPtr<T> {
  fn deref_mut(&mut self) -> &mut T {
    unsafe { &mut *self.ptr }
  }
}

impl<T> Clone for ManagedPtr<T> {
  fn clone(&self) -> ManagedPtr<T> {
    ManagedPtr { ptr: self.ptr }
  }
}

impl<T: fmt::Debug> fmt::Debug for ManagedPtr<T> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    unsafe { (*self.ptr).fmt(f) }
  }
}
