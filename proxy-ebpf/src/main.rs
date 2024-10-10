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
use aya_log_ebpf as log;
use core::hash::{Hash as _, Hasher as _};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};
use proxy_common::{
    fnv::{hash, hasher},
    IpAddr, SockAddr, SockAddrEntry,
};

#[no_mangle]
static TOKEN_SIZE: u16 = 7;

#[no_mangle]
static TOKEN_SIZE_4: u16 = 8;

/// The port that clients send packets to, to be routed to the appropriate agent. Network order.
#[no_mangle]
static EXTERNAL_PORT: u16 = u16::to_be(7777);
/// The IPv6 address for this host. Network order.
#[no_mangle]
static SRC_IPV6: [u8; 16] = [
    254, 128, 0, 0, 0, 0, 0, 0, 153, 240, 13, 207, 75, 227, 210, 90,
];
/// The IPv4 address for this host. Network order.
#[no_mangle]
static SRC_IPV4: u32 = u32::from_ne_bytes([192, 168, 1, 139]);
/// The MAC address that client -> server packets are forwarded to. This is likely
/// a router, as it _should_ work of the destination host is on the local network
/// or an external one
#[no_mangle]
static DEST_MAC: [u8; 6] = [0xc4, 0xea, 0x1d, 0xe3, 0x82, 0x4c];

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

#[repr(C)]
#[derive(Clone)]
struct Client {
    addr: SockAddr,
    mac: [u8; 6],
}

/// Maps a hash of a packet token to server endpoint
#[map]
static TARGET_ENDPOINTS: HashMap<u64, SockAddrEntry> =
    HashMap::<u64, SockAddrEntry>::with_max_entries(10, 0);
/// Maps a hash of a client endpoint and server endpoint to a port number
/// to use as the source port for sending the packet to a server
#[map]
static PAIR_TO_PORT: HashMap<u64, u16> = HashMap::<u64, u16>::with_max_entries(10, 0);
/// Maps a hash of a server endpoint and destination port to a client endpoint
#[map]
static SERVER_TO_CLIENT: HashMap<u64, Client> = HashMap::<u64, Client>::with_max_entries(10, 0);
/// Maps a hash of a server address to a queue of available ports
// #[map]
// static SERVER_TO_PORT: HashMap<u64, Queue<u16>> =
//     HashMap::<u64, Queue<u16>>::with_max_entries(10, 0);

// #[map]
// static SERVER_TO_PORT: HashOfMaps<u64, Queue<u16>> =
//     HashOfMaps::<u64, Queue<u16>>::with_max_entries(10);
#[map]
static PORT_QUEUE: Queue<u16> = Queue::with_max_entries(1000, 0);

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

const CLIENT4: u32 = u32::from_ne_bytes([192, 168, 1, 165]);
const CLIENT6: [u8; 16] = [
    254, 128, 0, 0, 0, 0, 0, 0, 193, 214, 100, 146, 90, 1, 49, 76,
];

#[repr(C)]
struct PseudoIpv4 {
    source: u32,
    dest: u32,
    zero: u8,
    proto: u8,
    length: u16,
}

#[repr(C)]
struct PseudoIpv6 {
    source: [u8; 16],
    dest: [u8; 16],
    length: u32,
    next_header: u32,
}

enum PseudoHdr {
    V4(PseudoIpv4),
    V6(PseudoIpv6),
}

struct UdpCalc {
    original: u32,
    pseudo: PseudoHdr,
}

fn try_proxy(ctx: XdpContext) -> Result<Action, ()> {
    let eth_hdr = unsafe { &mut *ptr_at::<EthHdr>(&ctx, 0)? };

    // Pull the source address and the destination port, ignoring non-UDP traffic
    let (src_addr, ip_hdr, udp_hdr) = unsafe {
        match eth_hdr.ether_type {
            EtherType::Ipv4 => {
                let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
                let v4hdr = &*ipv4hdr;

                match unsafe { v4hdr.proto } {
                    IpProto::Udp => unsafe {
                        let udp_hdr = &*ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                        (
                            proxy_common::SockAddr {
                                ip: IpAddr::V4(v4hdr.src_addr),
                                port: udp_hdr.source,
                            },
                            IpHdr::V4(ipv4hdr),
                            udp_hdr,
                        )
                    },
                    _ => {
                        return Err(());
                    }
                }
            }
            EtherType::Ipv6 => {
                let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;

                let v6hdr = &*ipv6hdr;

                log::warn!(&ctx, "GOT IPV6 PACKET {}", u16::from_be(v6hdr.payload_len));

                // Note this means that we ignore packets that have extensions
                match unsafe { v6hdr.next_hdr } {
                    IpProto::Udp => unsafe {
                        let udp_hdr = &*ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

                        (
                            proxy_common::SockAddr {
                                ip: IpAddr::V6(v6hdr.src_addr.in6_u.u6_addr8),
                                port: udp_hdr.source,
                            },
                            IpHdr::V6(ipv6hdr),
                            udp_hdr,
                        )
                    },
                    _ => {
                        return Err(());
                    }
                }
            }
            _ => {
                return Ok(xdp_action::XDP_PASS);
            }
        }
    };

    let port = udp_hdr.dest;
    let payload_len = u16::from_be(udp_hdr.len);

    match src_addr.ip {
        IpAddr::V4(v4) => {
            if v4 == CLIENT4 {
                log::info!(
                    &ctx,
                    "received packet from {:i}:{} to {}",
                    u32::from_be(v4),
                    u16::from_be(src_addr.port),
                    u16::from_be(port),
                );
            } else {
                return Err(());
            }
        }
        IpAddr::V6(v6) => {
            if v6 == CLIENT6 {
                log::info!(
                    &ctx,
                    "received packet from {:i}:{} to {}",
                    v6,
                    u16::from_be(src_addr.port),
                    u16::from_be(port),
                );
            } else {
                return Err(());
            }
        }
    }

    // If packet is sent to the external port, it's a client trying to reach a
    // server behind the proxy, in which case we determine which server based on
    // the token at the end of the packet
    let (dest_route, new_src_port, dest_mac) = if port == EXTERNAL_PORT {
        log::info!(
            &ctx,
            "got client packet: {} {}",
            u16::from_be(port),
            ip_hdr.len(),
        );

        // Read and hash the token
        let token_hash = unsafe {
            let mut slice = [0u8; TOKEN_SIZE as usize];

            if funcs::bpf_xdp_load_bytes(
                ctx.ctx,
                (EthHdr::LEN + ip_hdr.len() + payload_len as usize - TOKEN_SIZE as usize) as u32,
                &mut slice as *mut u8 as *mut _,
                TOKEN_SIZE as _,
            ) != 0
            {
                return Err(());
            }

            hash(&slice)
        };

        let dr = unsafe {
            if let Some(entry) = TARGET_ENDPOINTS.get(&token_hash) {
                //funcs::bpf_spin_lock(&entry.lock as *const _ as *mut _);
                let dr = entry.addr.clone();
                log::info!(&ctx, "got endpoint",);
                //funcs::bpf_spin_unlock(&entry.lock as *const _ as *mut _);
                dr
            } else {
                // TODO: push not found error with token to error ring buf
                log::info!(&ctx, "failed to find endpoint: {}", token_hash,);
                return Err(());
            }
        };

        let pair_key = {
            let mut h = hasher();
            src_addr.hash(&mut h);
            dr.hash(&mut h);
            h.finish()
        };

        log::info!(&ctx, "pair key {}", pair_key,);

        // Try to lookup the unique port to use for this connection between
        // client and server
        let src_port = if let Some(entry) = unsafe { PAIR_TO_PORT.get(&pair_key) } {
            log::info!(&ctx, "using source port {}", u16::from_be(*entry),);
            *entry
        } else {
            let Some(mut new_port) = PORT_QUEUE.pop() else {
                // TODO: push no available port error with token to error ring buf
                return Err(());
            };

            let server_port_hash = {
                let mut h = hasher();
                dr.hash(&mut h);
                h.write_u16(new_port);
                h.finish()
            };

            if unsafe { PAIR_TO_PORT.insert(&pair_key, &new_port, bindings::BPF_NOEXIST as _) }
                .is_ok()
            {
                log::info!(&ctx, "assigned server port hash {}", server_port_hash,);

                let client = Client {
                    addr: src_addr,
                    mac: eth_hdr.src_addr,
                };

                if let Err(err) = unsafe {
                    SERVER_TO_CLIENT.insert(&server_port_hash, &client, bindings::BPF_NOEXIST as _)
                } {
                    // TODO: push error
                    return Err(());
                }
            } else {
                // This means we got beat by a request on another CPU so just
                // query what port it got assigned and give back the port we were going to assign
                let _ = PORT_QUEUE.push(&new_port, 0);

                let Some(p) = (unsafe { PAIR_TO_PORT.get(&pair_key) }) else {
                    log::info!(&ctx, "failed to get port");
                    // TODO: push error
                    return Err(());
                };

                new_port = *p;
            }

            new_port
        };

        (dr, src_port, DEST_MAC)
    } else {
        // If the packet isn't sent to the external port, it might be a packet sent
        // from a server to a client, so try to lookup the client endpoint from
        // the unique source + dest port pair
        let server_port_hash = {
            let mut h = hasher();
            src_addr.hash(&mut h);
            h.write_u16(port);
            h.finish()
        };

        match src_addr.ip {
            IpAddr::V4(v4) => {
                if v4 == CLIENT4 {
                    log::info!(
                        &ctx,
                        "hash for {:i}:{} to {} {}",
                        u32::from_be(v4),
                        u16::from_be(src_addr.port),
                        u16::from_be(port),
                        server_port_hash,
                    );
                }
            }
            IpAddr::V6(v6) => {
                if v6 == CLIENT6 {
                    log::info!(
                        &ctx,
                        "hash for {:i}:{} to {} {}",
                        v6,
                        u16::from_be(src_addr.port),
                        u16::from_be(port),
                        server_port_hash,
                    );
                }
            }
        }

        let dr = if let Some(client_addr) = unsafe { SERVER_TO_CLIENT.get(&server_port_hash) } {
            client_addr.clone()
        } else {
            return Err(());
        };

        (dr.addr, EXTERNAL_PORT, dr.mac)
    };

    let packet_size_reduction = if port == EXTERNAL_PORT { TOKEN_SIZE } else { 0 };

    unsafe {
        let ip_common = match ip_hdr {
            IpHdr::V4(v4) => {
                let diff = if dest_route.is_ipv6() { 20 } else { 0 };

                IpCommon {
                    hop_limit: (*v4).ttl,
                    length: u16::from_be((*v4).tot_len) + diff - packet_size_reduction,
                }
            }
            IpHdr::V6(v6) => {
                let diff = if !dest_route.is_ipv6() { 20 } else { 0 };

                IpCommon {
                    hop_limit: (*v6).hop_limit,
                    length: u16::from_be((*v6).payload_len) - diff - packet_size_reduction,
                }
            }
        };

        let udp_calc = match dest_route.ip {
            IpAddr::V4(_) => None,
            IpAddr::V6(_) => {
                let pseudo = match ip_hdr {
                    IpHdr::V4(v4_hdr) => {
                        let v4_hdr = &*v4_hdr;
                        PseudoHdr::V4(PseudoIpv4 {
                            source: v4_hdr.src_addr,
                            dest: v4_hdr.dst_addr,
                            zero: 0,
                            proto: IpProto::Udp as _,
                            length: v4_hdr.tot_len,
                        })
                    }
                    IpHdr::V6(v6_hdr) => {
                        let v6_hdr = &*v6_hdr;
                        PseudoHdr::V6(PseudoIpv6 {
                            source: v6_hdr.src_addr.in6_u.u6_addr8,
                            dest: v6_hdr.dst_addr.in6_u.u6_addr8,
                            length: v6_hdr.payload_len as _,
                            next_header: IpProto::Udp as _,
                        })
                    }
                };

                Some(UdpCalc {
                    original: udp_hdr.check as u32,
                    pseudo,
                })
            }
        };

        rewrite_eth_hdr(&ctx, eth_hdr, dest_mac, &dest_route.ip)?;

        let udp_check = rewrite_ip_hdr(&ctx, &dest_route.ip, ip_common, udp_calc)?;
        rewrite_udp_hdr(
            &ctx,
            src_addr,
            dest_route,
            port,
            new_src_port,
            udp_check,
            payload_len,
            packet_size_reduction,
        )?;
    }

    match dest_route.ip {
        IpAddr::V4(v4) => {
            log::info!(
                &ctx,
                "retransmitting packet to {:i}:{} from {}",
                u32::from_be(v4),
                u16::from_be(dest_route.port),
                u16::from_be(new_src_port),
            );
        }
        IpAddr::V6(v6) => {
            log::info!(
                &ctx,
                "retransmitting packet to {:i}:{} from {}",
                v6,
                u16::from_be(dest_route.port),
                u16::from_be(new_src_port),
            );
        }
    }

    Ok(xdp_action::XDP_TX)
}

/// Rewrites the layer 2 ethernet header.
///
/// 1. Changes the source mac address to the destination (our) MAC address, and
/// the destination to the original client MAC if we are relaying a server packet,
/// or else to the MAC of the next hop, likely a router
/// 2. If changing ipv4 <-> ipv6, adjust the head of the packet up or down to account
/// for the change in size of the IP hdr
/// 3. Set the ethernet type in for the ethernet header if it has changed
unsafe fn rewrite_eth_hdr(
    ctx: &XdpContext,
    original: &mut EthHdr,
    dest_mac: [u8; 6],
    dest_ip: &IpAddr,
) -> Result<(), ()> {
    let (new_eth_type, adjust) = match (original.ether_type, dest_ip) {
        (EtherType::Ipv4, IpAddr::V4(_)) => (EtherType::Ipv4, 0),
        (EtherType::Ipv6, IpAddr::V6(_)) => (EtherType::Ipv6, 0),
        (EtherType::Ipv4, IpAddr::V6(_)) => (EtherType::Ipv6, -20),
        (EtherType::Ipv6, IpAddr::V4(_)) => (EtherType::Ipv4, 20),
        // Technically unreachable, but we can't actually use unreachable!
        _ => return Err(()),
    };

    // We need to save off the MAC as the call to bpf_xdp_adjust_head will
    // invalidate pointers, note that we do this here, instead of after the
    // if as there seems to be a verifier bug
    let src_addr = original.dst_addr;

    if adjust == 0 {
        original.src_addr = src_addr;
        original.dst_addr = dest_mac;
        return Ok(());
    }

    let ret = funcs::bpf_xdp_adjust_head(ctx.ctx, adjust);
    if ret != 0 {
        return Err(());
    }

    let eth_hdr = &mut *ptr_at::<EthHdr>(&ctx, 0)?;
    eth_hdr.src_addr = src_addr;
    eth_hdr.dst_addr = dest_mac;
    eth_hdr.ether_type = new_eth_type;

    Ok(())
}

/// Rewrites the layer 4 UDP header
///
/// 1. Changes the source and destination ports
/// 2. If removing the token from a client packet before forwarding to a server,
/// adjust the size in the header and adjust the packet tail
/// 3. Finalizes the UDP checksum calculation that was started when rewriting
/// the IP hdr, if we are sending an IPv6 packet
unsafe fn rewrite_udp_hdr(
    ctx: &XdpContext,
    src: SockAddr,
    dest: SockAddr,
    old_dest_port: u16,
    new_src_port: u16,
    mut udp_check: u32,
    payload_len: u16,
    packet_size_reduction: u16,
) -> Result<(), ()> {
    let off = match dest.ip {
        IpAddr::V4(dest_ip) => Ipv4Hdr::LEN,
        IpAddr::V6(dest_ip) => {
            let from = UdpHdr {
                source: src.port,
                dest: old_dest_port,
                len: u16::to_be(payload_len),
                check: 0,
            };

            let to = UdpHdr {
                source: new_src_port,
                dest: dest.port,
                len: u16::to_be(payload_len - packet_size_reduction),
                check: 0,
            };

            udp_check = funcs::bpf_csum_diff(
                &from as *const UdpHdr as *mut UdpHdr as *mut u32,
                core::mem::size_of::<UdpHdr>() as u32,
                &to as *const UdpHdr as *mut UdpHdr as *mut u32,
                core::mem::size_of::<UdpHdr>() as u32,
                udp_check,
            ) as u32;

            // If we're removing the token we need to load the original bytes
            // and do another diff
            if packet_size_reduction > 0 {
                // bpf_csum_diff requires size % 4 == 0
                let mut from = [0u8; TOKEN_SIZE_4 as usize];
                if funcs::bpf_xdp_load_bytes(
                    ctx.ctx,
                    (EthHdr::LEN + Ipv6Hdr::LEN + payload_len as usize - TOKEN_SIZE as usize)
                        as u32,
                    &mut from as *mut u8 as *mut _,
                    TOKEN_SIZE as _,
                ) != 0
                {
                    return Err(());
                }

                udp_check = funcs::bpf_csum_diff(
                    &mut from as *mut u8 as *mut u32,
                    TOKEN_SIZE_4 as _,
                    core::ptr::null_mut(),
                    0,
                    udp_check,
                ) as u32;
            }

            Ipv6Hdr::LEN
        }
    };

    // Remove the token from the end of the packet
    if packet_size_reduction > 0 {
        let err = funcs::bpf_xdp_adjust_tail(ctx.ctx, -(packet_size_reduction as i32));
        if err != 0 {
            // TODO: push error
            return Err(());
        }
    }

    let udp_hdr = &mut *ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + off)?;

    udp_hdr.source = new_src_port;
    udp_hdr.dest = dest.port;
    udp_hdr.len = u16::to_be(payload_len - packet_size_reduction);

    log::warn!(ctx, "set destination port to {}", u16::from_be(dest.port));

    if udp_check != 0 {
        udp_hdr.check = fold_checksum(udp_check);
    } else {
        udp_hdr.check = 0;
    }

    Ok(())
}

struct IpCommon {
    /// IPv6 payload_len, IPv4 tot_len
    length: u16,
    /// IPv6 hop limit, IPv4 ttl
    hop_limit: u8,
}

/// Rewrites the layer 3 IP hdr
///
/// 1. Changes the source and destination IP
/// 2. Changes the header packet size if removing the token from a client packet
/// 3. If sending an IPv4 packet, calculates the IPv4 checksum
/// 4. If sending an IPv6 packet, continue the UDP checksum calculation from
/// the original UDP checksum
unsafe fn rewrite_ip_hdr(
    ctx: &XdpContext,
    dest: &IpAddr,
    fields: IpCommon,
    udp_calc: Option<UdpCalc>,
) -> Result<u32, ()> {
    match dest {
        IpAddr::V4(v4_addr) => {
            let ip_hdr = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
            ip_hdr.write_bytes(0u8, 1);

            let ip_hdr = &mut *ip_hdr;
            ip_hdr.dst_addr = *v4_addr;
            ip_hdr.src_addr = SRC_IPV4;
            ip_hdr.proto = IpProto::Udp;
            ip_hdr.set_version(4);
            ip_hdr.set_ihl(5);
            ip_hdr.ttl = fields.hop_limit;
            ip_hdr.tot_len = u16::to_be(fields.length);

            // Since we are sending an IPv4 packet we can ignore setting the UDP
            // checksum, but must set the IPv4 checksum
            ipv4_l3_checksum(ip_hdr);
            Ok(0)
        }
        IpAddr::V6(v6_addr) => {
            let ip_hdr_ptr = ptr_at::<Ipv6Hdr>(ctx, EthHdr::LEN)?;
            ip_hdr_ptr.write_bytes(0u8, 1);

            let ip_hdr = &mut *ip_hdr_ptr;
            ip_hdr.dst_addr.in6_u.u6_addr8 = *v6_addr;
            ip_hdr.src_addr.in6_u.u6_addr8 = SRC_IPV6;
            ip_hdr.next_hdr = IpProto::Udp;
            ip_hdr.set_version(6);
            ip_hdr.hop_limit = fields.hop_limit;
            ip_hdr.payload_len = u16::to_be(fields.length);

            let Some(mut udp_calc) = udp_calc else {
                // unreachable!()
                return Err(());
            };

            // We don't want to calculate the full UDP checksum so we need to do
            // a diff against the original psuedo header
            let (from_ptr, from_size) = match &mut udp_calc.pseudo {
                PseudoHdr::V4(v4) => (
                    v4 as *mut PseudoIpv4 as *mut u32,
                    core::mem::size_of::<PseudoIpv4>(),
                ),
                PseudoHdr::V6(v6) => (
                    v6 as *mut PseudoIpv6 as *mut u32,
                    core::mem::size_of::<PseudoIpv6>(),
                ),
            };

            let ret = funcs::bpf_csum_diff(
                from_ptr,
                from_size as u32,
                ip_hdr_ptr as *mut _,
                Ipv6Hdr::LEN as _,
                udp_calc.original,
            );

            if ret < 0 {
                // TODO: error
                return Err(());
            }

            Ok(ret as _)
        }
    }
}

const EFAULT: i64 = 14;

// unsafe fn change_proto(ctx: &XdpContext, proto: EtherType) -> Result<(), i64> {
//     const MOVE_LEN: i32 = EthHdr::LEN as i32;

//     let len_diff: i32 = if proto == EtherType::Ipv6 {
//         // IPv4 -> IPv6
//         20
//     } else {
//         // IPv6 -> IPv4
//         -20
//     };

//     if len_diff < 0 {
//         let data = ctx.data() as i32;
//         let data_end = ctx.data_end() as i32;

//         if data + MOVE_LEN + -len_diff <= data_end {
//             // core::intrinsics::copy(
//             //     data as *const u8,
//             //     (data + -len_diff) as *mut u8,
//             //     MOVE_LEN as usize,
//             // );
//         } else {
//             return Err(EFAULT);
//         }
//     }

//     let ret = funcs::bpf_xdp_adjust_head(ctx.ctx, -len_diff);
//     if ret != 0 {
//         return Err(-ret);
//     }

//     if len_diff > 0 {
//         let data = ctx.data() as usize;
//         let data_end = ctx.data_end() as usize;

//         let original_start = data + len_diff as usize;

//         if original_start + MOVE_LEN as usize <= data_end {
//             // there is a bug somewhere (aya, kernel, llvm) where _this_
//             // core::intrinsics::copy is not found when loading the bytecode, so
//             // just do a hand-written copy
//             *(data as *mut u64) = *((original_start) as *const u64);
//             *((data + 8) as *mut u32) = *((original_start + 8) as *const u32);
//             *((data + 12) as *mut u16) = proto as u16;
//         } else {
//             return Err(EFAULT);
//         }
//     } else {
//         // Set the ether type
//         let ret = funcs::bpf_xdp_store_bytes(
//             ctx.ctx,
//             (EthHdr::LEN - core::mem::size_of::<EtherType>()) as u32,
//             &proto as *const EtherType as *mut u16 as *mut _,
//             core::mem::size_of::<EtherType>() as u32,
//         );
//         if ret != 0 {
//             return Err(-ret);
//         }
//     }

//     Ok(())
// }

#[inline]
fn fold_checksum(mut csum: u32) -> u16 {
    // *sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
    csum += 0xffff;

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

// unsafe fn v6_to_v4(
//     ctx: &XdpContext,
//     dst_addr: u32,
//     hdr: &Ipv6Hdr,
//     packet_size_reduction: u16,
// ) -> Result<(), ()> {
//     // Prep the Ipv4 header we are going to replace the ipv6 header with
//     let mut ip_hdr: Ipv4Hdr = core::mem::zeroed();
//     ip_hdr.dst_addr = dst_addr;
//     ip_hdr.src_addr = SRC_IPV4;
//     ip_hdr.proto = IpProto::Udp;
//     ip_hdr.set_version(4);
//     ip_hdr.set_ihl(5);
//     ip_hdr.ttl = hdr.hop_limit;
//     ip_hdr.tot_len = u16::to_be(
//         u16::from_be(hdr.payload_len) - 20 - packet_size_reduction, /* IPv6 header length - IPv4 header length */
//     );

//     // Adjust the head to remove the length difference between the IPv6 header and the IPv4 header
//     // we are replacing it with
//     change_proto(ctx, EtherType::Ipv4).map_err(|_| ())?;

//     ipv4_l3_checksum(&mut ip_hdr);

//     if funcs::bpf_xdp_store_bytes(
//         ctx.ctx,
//         EthHdr::LEN as _,
//         &mut ip_hdr as *mut Ipv4Hdr as *mut _,
//         core::mem::size_of_val(&ip_hdr) as _,
//     ) != 0
//     {
//         return Err(());
//     }

//     Ok(())
// }

// unsafe fn v4_to_v6(
//     ctx: &XdpContext,
//     dest_addr: &[u8; 16],
//     v4hdr: &Ipv4Hdr,
//     udp_check: &mut u32,
//     packet_size_reduction: u16,
// ) -> Result<(), ()> {
//     unsafe {
//         let from = PseudoIpv4 {
//             source: v4hdr.src_addr,
//             dest: v4hdr.dst_addr,
//             zero: 0,
//             proto: IpProto::Udp as _,
//             length: v4hdr.tot_len,
//         };

//         let to = PseudoIpv6 {
//             source: SRC_IPV6,
//             dest: *dest_addr,
//             length: (v4hdr.tot_len - packet_size_reduction) as _,
//             next_header: IpProto::Udp as _,
//         };

//         *udp_check = funcs::bpf_csum_diff(
//             &from as *const PseudoIpv4 as *mut PseudoIpv4 as *mut u32,
//             core::mem::size_of::<PseudoIpv4>() as u32,
//             &to as *const PseudoIpv6 as *mut PseudoIpv6 as *mut u32,
//             core::mem::size_of::<PseudoIpv6>() as u32,
//             *udp_check,
//         ) as _;
//     }

//     let mut ip_hdr: Ipv6Hdr = core::mem::zeroed();
//     ip_hdr.dst_addr.in6_u.u6_addr8 = *dest_addr;
//     ip_hdr.src_addr.in6_u.u6_addr8 = SRC_IPV6;
//     ip_hdr.next_hdr = IpProto::Udp;
//     ip_hdr.set_version(6);
//     ip_hdr.hop_limit = v4hdr.ttl;
//     ip_hdr.payload_len = u16::to_be(
//         u16::from_be(v4hdr.tot_len) + 20 - packet_size_reduction, /* IPv6 header length - IPv4 header length */
//     );

//     change_proto(ctx, EtherType::Ipv6).map_err(|_| ())?;

//     if funcs::bpf_xdp_store_bytes(
//         ctx.ctx,
//         EthHdr::LEN as _,
//         &mut ip_hdr as *mut Ipv6Hdr as *mut _,
//         core::mem::size_of_val(&ip_hdr) as _,
//     ) != 0
//     {
//         return Err(());
//     }

//     Ok(())
// }

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
