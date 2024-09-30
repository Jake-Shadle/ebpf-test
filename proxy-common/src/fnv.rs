//! This is the minimum neeed for this crate's use case, this is done because
//! the fnv crate has not seen a release in 4 years, even though the standalone
//! hash function was not added until last year

const INITIAL_STATE: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0100_0000_01b3;

#[inline]
pub fn hash(bytes: &[u8]) -> u64 {
    let mut hash = INITIAL_STATE;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}

#[inline]
pub fn hasher() -> impl core::hash::Hasher {
    pub struct FnvHasher(u64);

    impl core::hash::Hasher for FnvHasher {
        #[inline]
        fn finish(&self) -> u64 {
            self.0
        }

        #[inline]
        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 ^= u64::from(*byte);
                self.0 = self.0.wrapping_mul(PRIME);
            }
        }
    }

    FnvHasher(INITIAL_STATE)
}
