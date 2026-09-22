//! 4-way fingerprint cache for replay detection.
//!
//! Each of 8192 buckets holds four full fingerprints. A second distinct key
//! in the same bucket does not evict the first. The gate is best-effort when
//! many threads insert into one bucket at once.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const SLOTS: usize = 8192;
const WAYS: usize = 4;

pub struct SeenRing {
    slots: Vec<AtomicU64>,
    clock: Vec<AtomicU32>,
    hits: AtomicU32,
    inserts: AtomicU32,
}

impl Default for SeenRing {
    fn default() -> Self {
        Self::new()
    }
}

impl SeenRing {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(SLOTS * WAYS);
        for _ in 0..(SLOTS * WAYS) {
            slots.push(AtomicU64::new(0));
        }
        let mut clock = Vec::with_capacity(SLOTS);
        for _ in 0..SLOTS {
            clock.push(AtomicU32::new(0));
        }
        Self {
            slots,
            clock,
            hits: AtomicU32::new(0),
            inserts: AtomicU32::new(0),
        }
    }

    /// Returns true if `fp` was already present (replay).
    ///
    /// A fingerprint of 0 is stored as `u64::MAX` so an empty way stays 0.
    /// That aliases a real fingerprint of `u64::MAX` with the zero key.
    pub fn check_and_insert(&self, fp: u64) -> bool {
        let key = if fp == 0 { u64::MAX } else { fp };
        let slot = (key as usize) & (SLOTS - 1);
        let base = slot * WAYS;

        for way in 0..WAYS {
            if self.slots[base + way].load(Ordering::Relaxed) == key {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        for way in 0..WAYS {
            match self.slots[base + way].compare_exchange(
                0,
                key,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.inserts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                Err(prev) if prev == key => {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(_) => {}
            }
        }

        let way = (self.clock[slot].fetch_add(1, Ordering::Relaxed) as usize) % WAYS;
        let prev = self.slots[base + way].swap(key, Ordering::Relaxed);
        if prev == key {
            self.hits.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.inserts.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    pub fn count(&self) -> u32 {
        self.inserts.load(Ordering::Relaxed)
    }

    pub fn hits(&self) -> u32 {
        self.hits.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_insert_is_replay() {
        let ring = SeenRing::new();
        assert!(!ring.check_and_insert(0xAABB));
        assert!(ring.check_and_insert(0xAABB));
        assert_eq!(ring.hits(), 1);
    }

    #[test]
    fn zero_fingerprint_is_tracked() {
        let ring = SeenRing::new();
        assert!(!ring.check_and_insert(0));
        assert!(ring.check_and_insert(0));
    }

    #[test]
    fn same_bucket_keeps_both_keys() {
        let ring = SeenRing::new();
        let a = 1u64;
        let b = 1u64 + SLOTS as u64;
        assert_eq!(a as usize & (SLOTS - 1), b as usize & (SLOTS - 1));
        assert!(!ring.check_and_insert(a));
        assert!(!ring.check_and_insert(b));
        assert!(ring.check_and_insert(a));
        assert!(ring.check_and_insert(b));
    }
}
