#![no_std]

pub mod fnv;

/// Network byte order IP address
#[derive(Copy, Clone)]
#[repr(C)]
pub enum IpAddr {
    V4(u32),
    V6([u8; 16]),
}

/// Network byte order socket address
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SockAddr {
    pub ip: IpAddr,
    /// Network order
    pub port: u16,
}

impl core::hash::Hash for SockAddr {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self.ip {
            IpAddr::V4(v4) => {
                state.write_u32(v4);
            }
            IpAddr::V6(v6) => {
                state.write(&v6);
            }
        }

        state.write_u16(self.port);
    }
}

/// The eBPF compiler will recognize the use of bpf_spin_lock, which allows the
/// user space code to use `BPF_F_LOCK` to update individual elements atomically
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockAddrEntry {
    //lock: bindings::bpf_spin_lock,
    pub addr: SockAddr,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SockAddrEntry {}
