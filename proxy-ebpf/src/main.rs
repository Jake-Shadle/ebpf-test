#![no_std]
#![no_main]

// References:
// https://stackoverflow.com/questions/74144705/forward-http-requests-to-another-webserver-port-bpf-xdp
// https://github.com/cilium/cilium/blob/main/bpf/bpf_xdp.c
// https://fly.io/blog/bpf-xdp-packet-filters-and-udp/
// https://konghq.com/blog/engineering/writing-an-ebpf-xdp-load-balancer-in-rust
// https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

use aya_ebpf::{
    bindings::{self, xdp_action},
    helpers::r#gen as funcs,
    macros::{map, xdp},
    maps::{HashMap, Queue},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::hash::{Hash as _, Hasher as _};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};
use proxy_common::{IpAddr, SockAddr, SockAddrEntry};

#[no_mangle]
static TOKEN_SIZE: i32 = 0;

/// The port that clients send packets to, to be routed to the appropriate agent. Network order.
#[no_mangle]
static EXTERNAL_PORT: u16 = 0;
/// The IPv6 address for this host. Network order.
#[no_mangle]
static SRC_IPV6: [u8; 16] = [0u8; 16];
/// The IPv4 address for this host. Network order.
#[no_mangle]
static SRC_IPV4: u32 = 0;

type Action = xdp_action::Type;

enum IpHdr {
    V4(*mut Ipv4Hdr),
    V6(*mut Ipv6Hdr),
}

impl IpHdr {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::V4(_) => Ipv4Hdr::LEN,
            Self::V6(_) => Ipv6Hdr::LEN,
        }
    }
}

/// Maps a hash of a packet token to server endpoint
#[map(name = "TARGET_ENDPOINTS")]
static TARGET_ENDPOINTS: HashMap<u64, SockAddrEntry> =
    HashMap::<u64, SockAddrEntry>::with_max_entries(100000, 0);
/// Maps a hash of a client endpoint and server endpoint to a port number
/// to use as the source port for sending the packet to a server
#[map(name = "PAIR_TO_PORT")]
static PAIR_TO_PORT: HashMap<u64, u16> = HashMap::<u64, u16>::with_max_entries(100000, 0);
/// Maps a hash of a server endpoint and destination port to a client endpoint
#[map(name = "SERVER_TO_CLIENT")]
static SERVER_TO_CLIENT: HashMap<u64, SockAddr> =
    HashMap::<u64, SockAddr>::with_max_entries(100000, 0);
/// Maps a hash of a server address to a queue of available ports
#[map(name = "SERVER_TO_PORT")]
static SERVER_TO_PORT: HashMap<u64, Queue<u16>> =
    HashMap::<u64, Queue<u16>>::with_max_entries(100000, 0);

/// Helper function to get a pointer to a type at the specified offset from
/// the start of the context.
///
/// This is important as we check that the requested data is within the bounds
/// of the provided buffer, which is required to pass the eBPF validator
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

fn try_proxy(ctx: XdpContext) -> Result<Action, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;

    // Pull the source address and the destination port, ignoring non-UDP traffic
    let (src_addr, ip_hdr, udp_hdr) = match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;

            match unsafe { (*ipv4hdr).proto } {
                IpProto::Udp => unsafe {
                    let udp_hdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                    (
                        proxy_common::SockAddr {
                            ip: IpAddr::V4((*ipv4hdr).src_addr),
                            port: (*udp_hdr).source,
                        },
                        IpHdr::V4(ipv4hdr),
                        udp_hdr,
                    )
                },
                _ => return Err(()),
            }
        }
        EtherType::Ipv6 => {
            let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;

            // Note this means that we ignore packets that have extensions
            match unsafe { (*ipv6hdr).next_hdr } {
                IpProto::Udp => unsafe {
                    let udp_hdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

                    (
                        proxy_common::SockAddr {
                            ip: IpAddr::V6((*ipv6hdr).src_addr.in6_u.u6_addr8),
                            port: (*udp_hdr).source,
                        },
                        IpHdr::V6(ipv6hdr),
                        udp_hdr,
                    )
                },
                _ => return Err(()),
            }
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let (port, payload_len) = unsafe { ((*udp_hdr).dest, u16::from_be((*udp_hdr).len)) };

    // If packet is sent to the external port, it's a client trying to reach a
    // server behind the proxy, in which case we determine which server based on
    // the token at the end of the packet
    let (dest_route, src_port) = if port == EXTERNAL_PORT {
        // Read and hash the token
        let token_hash = unsafe {
            // Just ensure the token is not longer than the actual data portion of the datagram
            let data_start = EthHdr::LEN + ip_hdr.len() + core::mem::size_of::<UdpHdr>();
            let token_start = ctx.data_end() - TOKEN_SIZE as usize;
            if token_start < data_start {
                return Err(());
            }

            seahash::hash(core::slice::from_raw_parts(
                token_start as *const u8,
                TOKEN_SIZE as usize,
            ))
        };

        let dr = unsafe {
            if let Some(entry) = TARGET_ENDPOINTS.get(&token_hash) {
                //funcs::bpf_spin_lock(&entry.lock as *const _ as *mut _);
                let dr = entry.addr.clone();
                //funcs::bpf_spin_unlock(&entry.lock as *const _ as *mut _);
                dr
            } else {
                // TODO: push not found error with token to error ring buf
                return Err(());
            }
        };

        let pair_key = {
            let mut h = seahash::SeaHasher::new();
            src_addr.hash(&mut h);
            dr.hash(&mut h);
            h.finish()
        };

        // Try to lookup the unique port to use for this connection between
        // client and server
        let src_port = if let Some(entry) = unsafe { PAIR_TO_PORT.get(&pair_key) } {
            *entry
        } else {
            let server_hash = {
                let mut h = seahash::SeaHasher::new();
                dr.hash(&mut h);
                h.finish()
            };

            // Otherwise we need to assign an unassigned port to this pair. Since
            // we aren't actually using ports for anything other than knowing which
            // client to send server packets back to they only need to be unique per
            // server
            let mut new_port = if let Some(queue) = unsafe { SERVER_TO_PORT.get(&server_hash) } {
                let Some(np) = queue.pop() else {
                    // TODO: push no available port error with token to error ring buf
                    return Err(());
                };

                np
            } else {
                // TODO: push not found error with token to error ring buf
                return Err(());
            };

            let server_port_hash = {
                let mut h = seahash::SeaHasher::new();
                dr.hash(&mut h);
                h.write_u16(new_port);
                h.finish()
            };

            if unsafe { PAIR_TO_PORT.insert(&pair_key, &new_port, bindings::BPF_NOEXIST as _) }
                .is_ok()
            {
                if let Err(err) = unsafe {
                    SERVER_TO_CLIENT.insert(
                        &server_port_hash,
                        &src_addr,
                        bindings::BPF_NOEXIST as _,
                    )
                } {
                    // TODO: push error
                    return Err(());
                }
            } else {
                // This means we got beat by another CPU so just query what port it got assigned
                // and give back the port we were going to assign
                if let Some(queue) = unsafe { SERVER_TO_PORT.get(&server_hash) } {
                    // If the queue is full that is up the host program to fixup
                    let _ = queue.push(&new_port, 0);
                }

                let Some(p) = (unsafe { PAIR_TO_PORT.get(&pair_key) }) else {
                    // TODO: push error
                    return Err(());
                };

                new_port = *p;
            }

            new_port
        };

        (dr, src_port)
    } else {
        // If the packet isn't sent to the external port, it might be a packet sent
        // from a server to a client, so try to lookup the client endpoint from
        // the unique source + dest port pair
        let server_port_hash = {
            let mut h = seahash::SeaHasher::new();
            src_addr.hash(&mut h);
            h.write_u16(port);
            h.finish()
        };

        let dr = if let Some(client_addr) = unsafe { SERVER_TO_CLIENT.get(&server_port_hash) } {
            client_addr.clone()
        } else {
            return Err(());
        };

        (dr, EXTERNAL_PORT)
    };

    let payload_len = payload_len
        - if port == EXTERNAL_PORT {
            TOKEN_SIZE as u16
        } else {
            0
        };

    unsafe {
        rewrite_ip_hdr(&ctx, &dest_route.ip, ip_hdr)?;
        rewrite_udp_hdr(
            &ctx,
            dest_route,
            src_port,
            payload_len,
            if port == EXTERNAL_PORT {
                -TOKEN_SIZE
            } else {
                0
            },
        )?;
    }

    Ok(xdp_action::XDP_TX)
}

unsafe fn rewrite_udp_hdr(
    ctx: &XdpContext,
    dest: SockAddr,
    src_port: u16,
    payload_len: u16,
    tail_adjust: i32,
) -> Result<(), ()> {
    if tail_adjust != 0 {
        let err = funcs::bpf_xdp_adjust_tail(ctx.ctx, tail_adjust);
        if err != 0 {
            // TODO: push error
            return Err(());
        }
    }

    let (csum, off) = match dest.ip {
        IpAddr::V4(dest_ip) => {
            #[repr(C)]
            struct PseudoIpv4 {
                source: u32,
                dest: u32,
                zero: u8,
                proto: u8,
                length: u16,
            }

            let pseudo = PseudoIpv4 {
                source: SRC_IPV4,
                dest: dest_ip,
                zero: 0,
                proto: IpProto::Udp as _,
                length: u16::to_be(payload_len),
            };

            (
                funcs::bpf_csum_diff(
                    core::ptr::null_mut(),
                    0,
                    &pseudo as *const PseudoIpv4 as *mut PseudoIpv4 as *mut u32,
                    core::mem::size_of::<PseudoIpv4>() as u32,
                    0,
                ) as u32,
                Ipv4Hdr::LEN,
            )
        }
        IpAddr::V6(dest_ip) => {
            #[repr(C)]
            struct PseudoIpv6 {
                source: [u8; 16],
                dest: [u8; 16],
                length: u32,
                next_header: u32,
            }

            let pseudo = PseudoIpv6 {
                source: SRC_IPV6,
                dest: dest_ip,
                length: u32::to_be(payload_len as u32),
                next_header: IpProto::Udp as _,
            };

            (
                funcs::bpf_csum_diff(
                    core::ptr::null_mut(),
                    0,
                    &pseudo as *const PseudoIpv6 as *mut PseudoIpv6 as *mut u32,
                    core::mem::size_of::<PseudoIpv6>() as u32,
                    0,
                ) as u32,
                Ipv6Hdr::LEN,
            )
        }
    };

    let udp_hdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + off)?;

    let udp_hdr = &mut *udp_hdr;
    udp_hdr.source = src_port;
    udp_hdr.dest = dest.port;
    udp_hdr.len = u16::to_be(payload_len);
    udp_hdr.check = fold_checksum(csum);

    Ok(())
}

unsafe fn rewrite_ip_hdr(ctx: &XdpContext, dest: &IpAddr, hdr: IpHdr) -> Result<(), ()> {
    // For the simple cases of ipv4 -> ipv4 and ipv6 -> ipv6 we can just directly
    // set the ip and move on
    match (dest, hdr) {
        (IpAddr::V4(dest_addr), IpHdr::V4(hdr)) => {
            let hdr = &mut *hdr;

            hdr.src_addr = hdr.dst_addr;
            hdr.dst_addr = *dest_addr;

            ipv4_l3_checksum(hdr);
        }
        (IpAddr::V6(dest_addr), IpHdr::V6(hdr)) => {
            let hdr = unsafe { &mut *hdr };
            hdr.src_addr = hdr.dst_addr;
            hdr.dst_addr.in6_u.u6_addr8 = *dest_addr;
        }
        (IpAddr::V4(dest_addr), IpHdr::V6(hdr)) => {
            v6_to_v4(ctx, *dest_addr, hdr)?;
        }
        (IpAddr::V6(dest_addr), IpHdr::V4(hdr)) => {
            v4_to_v6(ctx, dest_addr, hdr)?;
        }
    }

    Ok(())
}

// pub struct Ipv4Hdr {
//     pub _bitfield_align_1: [u8; 0],
//     pub _bitfield_1: BitfieldUnit<[u8; 1]>,
//     pub tos: u8,
//     pub tot_len: u16,
//     pub id: u16,
//     pub frag_off: u16,
//     pub ttl: u8,
//     pub proto: IpProto,
//     pub check: u16,
//     pub src_addr: u32,
//     pub dst_addr: u32,
// }

// pub struct Ipv6Hdr {
//     pub _bitfield_align_1: [u8; 0],
//     pub _bitfield_1: BitfieldUnit<[u8; 1]>,
//     pub flow_label: [u8; 3],
//     pub payload_len: u16,
//     pub next_hdr: IpProto,
//     pub hop_limit: u8,
//     pub src_addr: in6_addr,
//     pub dst_addr: in6_addr,
// }

// IPV4
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// ┌───────┬───────┬───────────────┬───────────────────────────────┐
// │Version│  IHL  │Type of Service│          Total Length         │
// ├───────┴───────┴───────────────┼─────┬─────────────────────────┤
// │         Identification        │Flags│     Fragment Offset     │
// ├───────────────┬───────────────┼─────┴─────────────────────────┤
// │  Time to Live │    Protocol   │        Header Checksum        │
// ├───────────────┴───────────────┴───────────────────────────────┤
// │                         Source Address                        │
// ├───────────────────────────────────────────────────────────────┤
// │                      Destination Address                      │
// ├───────────────────────────────────────────────┬───────────────┤
// │                    Options                    │    Padding    │
// └───────────────────────────────────────────────┴───────────────┘

// IPV6
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// ┌───────┬───────────────┬───────────────────────────────────────┐
// │Version│ Traffic Class │               Flow Label              │
// ├───────┴───────────────┴───────┬───────────────┬───────────────┤
// │         Payload Length        │  Next Header  │   Hop Limit   │
// ├───────────────────────────────┴───────────────┴───────────────┤
// │                                                               │
// ├                                                               ┤
// │                                                               │
// ├                         Source Address                        ┤
// │                                                               │
// ├                                                               ┤
// │                                                               │
// ├───────────────────────────────────────────────────────────────┤
// │                                                               │
// ├                                                               ┤
// │                                                               │
// ├                       Destination Address                     ┤
// │                                                               │
// ├                                                               ┤
// │                                                               │
// └───────────────────────────────────────────────────────────────┘

// #[repr(packed)]
// #[derive(Copy, Clone)]
// struct Parts {
//     p1: u32,
//     p2: u32,
//     p3: u32,
//     p4: u32,
// }

// #[repr(packed)]
// union V6Addr {
//     parts: Parts,
//     addr: [u8; 16],
// }

const EFAULT: i64 = 14;

unsafe fn change_proto(ctx: &XdpContext, proto: EtherType) -> Result<(), i64> {
    const MOVE_LEN: i32 = EthHdr::LEN as i32;

    let len_diff: i32 = if proto == EtherType::Ipv6 {
        // IPv4 -> IPv6
        20
    } else {
        // IPv6 -> IPv4
        -20
    };

    if len_diff < 0 {
        let data = ctx.data() as i32;
        let data_end = ctx.data_end() as i32;

        if data + MOVE_LEN + -len_diff <= data_end {
            core::intrinsics::copy(
                data as *const u8,
                (data + -len_diff) as *mut u8,
                MOVE_LEN as usize,
            );
        } else {
            return Err(EFAULT);
        }
    }

    let ret = funcs::bpf_xdp_adjust_head(ctx.ctx, -len_diff);
    if ret != 0 {
        return Err(-ret);
    }

    if len_diff > 0 {
        let data = ctx.data() as i32;
        let data_end = ctx.data_end() as i32;

        if data + MOVE_LEN + len_diff <= data_end {
            core::intrinsics::copy(
                (data + len_diff) as *const u8,
                data as *mut u8,
                MOVE_LEN as usize,
            );
        } else {
            return Err(EFAULT);
        }
    }

    // Set the ether type
    let ret = funcs::bpf_xdp_store_bytes(
        ctx.ctx,
        (EthHdr::LEN - core::mem::size_of::<EtherType>()) as u32,
        &proto as *const EtherType as *mut u16 as *mut _,
        core::mem::size_of::<EtherType>() as u32,
    );
    if ret != 0 {
        return Err(-ret);
    }

    Ok(())
}

#[inline]
fn fold_checksum(mut csum: u32) -> u16 {
    // *sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
    csum += 0xffff;
    csum += 1;

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

#[inline]
unsafe fn ipv4_l3_checksum(ip_hdr: &mut Ipv4Hdr) {
    // Just to be sure
    ip_hdr.check = 0;

    let csum = funcs::bpf_csum_diff(
        core::ptr::null_mut(),
        0,
        ip_hdr as *mut Ipv4Hdr as *mut _,
        Ipv4Hdr::LEN as _,
        0,
    ) as u32;

    ip_hdr.check = fold_checksum(csum);
}

unsafe fn v6_to_v4(ctx: &XdpContext, dst_addr: u32, hdr: *mut Ipv6Hdr) -> Result<(), ()> {
    // Prep the Ipv4 header we are going to replace the ipv6 header with
    let mut ip_hdr: Ipv4Hdr = core::mem::zeroed();
    ip_hdr.dst_addr = dst_addr;
    ip_hdr.src_addr = SRC_IPV4;
    ip_hdr.proto = IpProto::Udp;
    ip_hdr.set_version(4);
    ip_hdr.set_ihl(5);
    ip_hdr.ttl = (*hdr).hop_limit;
    ip_hdr.tot_len = u16::to_be(
        u16::from_be((*hdr).payload_len) - 20, /* IPv6 header length - IPv4 header length */
    );

    // Adjust the head to remove the length difference between the IPv6 header and the IPv4 header
    // we are replacing it with
    change_proto(ctx, EtherType::Ipv4).map_err(|_| ())?;

    ipv4_l3_checksum(&mut ip_hdr);

    if funcs::bpf_xdp_store_bytes(
        ctx.ctx,
        EthHdr::LEN as _,
        &mut ip_hdr as *mut Ipv4Hdr as *mut _,
        core::mem::size_of_val(&ip_hdr) as _,
    ) != 0
    {
        return Err(());
    }

    Ok(())
}

unsafe fn v4_to_v6(ctx: &XdpContext, dest_addr: &[u8; 16], hdr: *mut Ipv4Hdr) -> Result<(), ()> {
    let mut ip_hdr: Ipv6Hdr = core::mem::zeroed();
    ip_hdr.dst_addr.in6_u.u6_addr8 = *dest_addr;
    ip_hdr.src_addr.in6_u.u6_addr8 = SRC_IPV6;
    ip_hdr.next_hdr = IpProto::Udp;
    ip_hdr.set_version(6);
    ip_hdr.hop_limit = (*hdr).ttl;
    ip_hdr.payload_len = u16::to_be(
        u16::from_be((*hdr).tot_len) + 20, /* IPv6 header length - IPv4 header length */
    );

    change_proto(ctx, EtherType::Ipv6).map_err(|_| ())?;

    if funcs::bpf_xdp_store_bytes(
        ctx.ctx,
        EthHdr::LEN as _,
        &mut ip_hdr as *mut Ipv6Hdr as *mut _,
        core::mem::size_of_val(&ip_hdr) as _,
    ) != 0
    {
        return Err(());
    }

    Ok(())
}

/// The "main" of our program
#[xdp]
pub fn proxy(ctx: XdpContext) -> Action {
    match try_proxy(ctx) {
        Ok(ret) => ret,
        Err(_ret) => xdp_action::XDP_PASS,
    }
}

/// We can't panic, but we still need to satisfy the linker
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
