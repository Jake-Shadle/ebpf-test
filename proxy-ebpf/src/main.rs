#![no_std]
#![no_main]
// There are some commented out things that I'm keeping in since I'm going back to them
#![allow(dead_code)]

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

/// The length of the token (in bytes) used by clients to specify the server
/// they wish to communicate with
#[no_mangle]
static TOKEN_SIZE: u8 = 0;
/// The maximum token size in bytes
const TOKEN_MAX: usize = 16;
/// The port that clients send packets to, to be routed to the appropriate agent. Network order.
#[no_mangle]
static EXTERNAL_PORT: u16 = 0;
/// The IPv6 address for this host.
#[no_mangle]
static SRC_IPV6: [u8; 16] = [0u8; 16];
/// The IPv4 address for this host. Network order.
#[no_mangle]
static SRC_IPV4: u32 = 0;
/// The MAC address that client -> server packets are forwarded to. This is likely
/// a router, as it _should_ work if the destination host is on the local network
/// or an external one
#[no_mangle]
static DEST_MAC: [u8; 6] = [0u8; 6];

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
    original: u16,
    pseudo: PseudoHdr,
}

/// Helper macro to read global variables
///
/// Due to how eBPF loaders (aya, bpftool etc) set globals, we unfortunately need
/// to use read_volatile every time we access a static global, even though they are
/// only ever set at program load
macro_rules! read_global {
    ($name:ident) => {{
        unsafe { core::ptr::read_volatile(&$name) }
    }};
}

/// Temp helper macro
macro_rules! ohno {
    ($ctx:expr, $func:expr) => {{
        let ret = $func;
        if ret < 0 {
            log::error!($ctx, "bpf_csum_diff failed with {}", ret);
            return Err(());
        }

        ret
    }};
}

/// The core of the program
///
/// 1. Determines if the packet is possibly of interest to the proxy, ie. is an
/// IPv4 or IPv6 UDP packet
/// 2. Attempts to lookup an appropriate destination server if the packet is sent
/// to the [`EXTERNAL_PORT`] that clients use, by looking up the address by computing
/// a checksum of the token expected at the end of the packet data
/// 3. If not sent to [`EXTERNAL_PORT`], determine if the packet is being sent to
/// a port that has been assigned to that particular client -> server session, and
/// if so forward that packet to that client
///
/// If a destination (client or server) is not determined, we `XDP_PASS` the packet
/// up the network stack
///
/// Otherwise, we transform the packet, changing the destination IP/port to the
/// new target, and changing the source IP this host and the source port to either
/// the same [`EXTERNAL_PORT`] for sending packets to the client, or the unique
/// port used for the client <-> server session so that we can identify the client
/// to forward packets to when the server sends packets to this host on that port
///
/// Finally, the token is stripped from the packet if it is a client packet before
/// being forwarded to the server
fn try_proxy(ctx: XdpContext) -> Result<Action, ()> {
    let eth_hdr = unsafe { &mut *ptr_at::<EthHdr>(&ctx, 0)? };

    // Pull the source address and the destination port, ignoring non-IPv4/IPv6 + UDP traffic
    let (src_addr, ip_hdr, udp_hdr) = unsafe {
        match eth_hdr.ether_type {
            EtherType::Ipv4 => {
                let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
                let v4hdr = &*ipv4hdr;

                match v4hdr.proto {
                    IpProto::Udp => {
                        let udp_hdr = &*ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                        (
                            proxy_common::SockAddr {
                                ip: IpAddr::V4(v4hdr.src_addr),
                                port: udp_hdr.source,
                            },
                            IpHdr::V4(ipv4hdr),
                            udp_hdr,
                        )
                    }
                    _ => {
                        return Err(());
                    }
                }
            }
            EtherType::Ipv6 => {
                let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;

                let v6hdr = &*ipv6hdr;

                // Note this means that we ignore packets that have extensions
                match v6hdr.next_hdr {
                    IpProto::Udp => {
                        let udp_hdr = &*ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

                        (
                            proxy_common::SockAddr {
                                ip: IpAddr::V6(v6hdr.src_addr.in6_u.u6_addr8),
                                port: udp_hdr.source,
                            },
                            IpHdr::V6(ipv6hdr),
                            udp_hdr,
                        )
                    }
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

    let external_port = read_global!(EXTERNAL_PORT);

    // If packet is sent to the external port, it's a client trying to reach a
    // server behind the proxy, in which case we determine which server based on
    // the token at the end of the packet
    let (dest_route, new_src_port, dest_mac, packet_size_reduction) = if port == external_port {
        let tok_size = read_global!(TOKEN_SIZE);

        // Read and hash the token
        let token_hash = unsafe {
            let mut slice = [0u8; TOKEN_MAX];

            if funcs::bpf_xdp_load_bytes(
                ctx.ctx,
                (EthHdr::LEN + ip_hdr.len() + payload_len as usize - tok_size as usize) as u32,
                &mut slice as *mut u8 as *mut _,
                tok_size as _,
            ) != 0
            {
                return Err(());
            }

            hash(&slice[..tok_size as usize])
        };

        let dr = unsafe {
            if let Some(entry) = TARGET_ENDPOINTS.get(&token_hash) {
                entry.addr.clone()
            } else {
                // TODO: push not found error with token to error ring buf
                return Err(());
            }
        };

        let pair_key = {
            let mut h = hasher();
            src_addr.hash(&mut h);
            dr.hash(&mut h);
            h.finish()
        };

        // Try to lookup the unique port to use for this connection between
        // client and server
        let src_port = if let Some(entry) = unsafe { PAIR_TO_PORT.get(&pair_key) } {
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

            if PAIR_TO_PORT
                .insert(&pair_key, &new_port, bindings::BPF_NOEXIST as _)
                .is_ok()
            {
                log::info!(&ctx, "assigned server port hash {}", server_port_hash,);

                let client = Client {
                    addr: src_addr,
                    mac: eth_hdr.src_addr,
                };

                if let Err(_err) =
                    SERVER_TO_CLIENT.insert(&server_port_hash, &client, bindings::BPF_NOEXIST as _)
                {
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

        (dr, src_port, read_global!(DEST_MAC), tok_size as u16)
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

        let dr = if let Some(client_addr) = unsafe { SERVER_TO_CLIENT.get(&server_port_hash) } {
            client_addr.clone()
        } else {
            return Err(());
        };

        (dr.addr, external_port, dr.mac, 0)
    };

    unsafe {
        let ip_common = match ip_hdr {
            IpHdr::V4(v4) => IpCommon {
                hop_limit: (*v4).ttl,
                data_length: u16::from_be((*v4).tot_len) - Ipv4Hdr::LEN as u16,
            },
            IpHdr::V6(v6) => IpCommon {
                hop_limit: (*v6).hop_limit,
                data_length: u16::from_be((*v6).payload_len),
            },
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

                        let pseudo = PseudoIpv6 {
                            source: v6_hdr.src_addr.in6_u.u6_addr8,
                            dest: v6_hdr.dst_addr.in6_u.u6_addr8,
                            length: v6_hdr.payload_len as _,
                            next_header: (IpProto::Udp as u32).to_be(),
                        };

                        PseudoHdr::V6(pseudo)
                    }
                };

                Some(UdpCalc {
                    original: udp_hdr.check,
                    pseudo,
                })
            }
        };

        rewrite_eth_hdr(&ctx, eth_hdr, dest_mac, &dest_route.ip)?;

        let udp_check = rewrite_ip_hdr(
            &ctx,
            &dest_route.ip,
            ip_common,
            udp_calc,
            packet_size_reduction,
        )?;
        rewrite_udp_hdr(
            &ctx,
            src_addr,
            dest_route,
            port,
            new_src_port,
            udp_check,
            ip_common,
            packet_size_reduction,
        )?;
    }

    // match dest_route.ip {
    //     IpAddr::V4(v4) => {
    //         log::info!(
    //             &ctx,
    //             "retransmitting packet to {:i}:{} from {}",
    //             u32::from_be(v4),
    //             u16::from_be(dest_route.port),
    //             u16::from_be(new_src_port),
    //         );
    //     }
    //     IpAddr::V6(v6) => {
    //         log::info!(
    //             &ctx,
    //             "retransmitting packet to {:i}:{} from {}",
    //             v6,
    //             u16::from_be(dest_route.port),
    //             u16::from_be(new_src_port),
    //         );

    //         let size = EthHdr::LEN + Ipv6Hdr::LEN + UdpHdr::LEN + 4;
    //         if ctx.data() + size > ctx.data_end() {
    //             return Err(());
    //         }

    //         let slice = unsafe { core::slice::from_raw_parts(ctx.data() as *const u8, size) };

    //         log::info!(&ctx, "new packet {:x}", &slice[..]);
    //     }
    // }

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

#[derive(Copy, Clone)]
struct IpCommon {
    /// The length of the UdpHdr and data section of the packet
    data_length: u16,
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
    packet_size_reduction: u16,
) -> Result<u32, ()> {
    match dest {
        IpAddr::V4(v4_addr) => {
            let ip_hdr = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
            ip_hdr.write_bytes(0u8, 1);

            let ip_hdr = &mut *ip_hdr;
            ip_hdr.dst_addr = *v4_addr;
            ip_hdr.src_addr = read_global!(SRC_IPV4);
            ip_hdr.proto = IpProto::Udp;
            ip_hdr.set_version(4);
            ip_hdr.set_ihl(5);
            ip_hdr.ttl = fields.hop_limit;
            ip_hdr.tot_len =
                u16::to_be(fields.data_length + Ipv4Hdr::LEN as u16 - packet_size_reduction);

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
            ip_hdr.src_addr.in6_u.u6_addr8 = read_global!(SRC_IPV6);
            ip_hdr.next_hdr = IpProto::Udp;
            ip_hdr.set_version(6);
            ip_hdr.hop_limit = fields.hop_limit;
            ip_hdr.payload_len = u16::to_be(fields.data_length - packet_size_reduction);

            let Some(_udp_calc) = udp_calc else {
                // unreachable!()
                return Err(());
            };

            // let seed = !udp_calc.original as u32;
            // let orig_csum = udp_calc.original as u32;
            // let ret = ohno!(ctx, funcs::bpf_csum_diff(core::ptr::null_mut(), 0, &orig_csum as *const u32 as *mut u32, 4, seed)) as u32;

            // // We don't want to calculate the full UDP checksum so we need to do
            // // a diff against the original psuedo header
            // let (from_ptr, from_size) = match &mut udp_calc.pseudo {
            //     PseudoHdr::V4(v4) => (
            //         v4 as *mut PseudoIpv4 as *mut u32,
            //         core::mem::size_of::<PseudoIpv4>(),
            //     ),
            //     PseudoHdr::V6(v6) => (
            //         v6 as *mut PseudoIpv6 as *mut u32,
            //         core::mem::size_of::<PseudoIpv6>(),
            //     ),
            // };

            let to = PseudoIpv6 {
                source: ip_hdr.src_addr.in6_u.u6_addr8,
                dest: ip_hdr.dst_addr.in6_u.u6_addr8,
                length: u32::to_be(fields.data_length as u32 - packet_size_reduction as u32),
                next_header: (IpProto::Udp as u32).to_be(),
            };

            let ret = ohno!(
                ctx,
                funcs::bpf_csum_diff(
                    //from_ptr,
                    //from_size as u32,
                    core::ptr::null_mut(),
                    0,
                    &to as *const PseudoIpv6 as *mut PseudoIpv6 as *mut _,
                    core::mem::size_of::<PseudoIpv6>() as _,
                    0,
                )
            );

            // if ret < 0 {
            //     // TODO: error
            //     return Err(());
            // }

            Ok(ret as _)
        }
    }
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
    _src: SockAddr,
    dest: SockAddr,
    _old_dest_port: u16,
    new_src_port: u16,
    mut udp_check: u32,
    ip_common: IpCommon,
    packet_size_reduction: u16,
) -> Result<(), ()> {
    let off = match dest.ip {
        IpAddr::V4(_dest_ip) => Ipv4Hdr::LEN,
        IpAddr::V6(_dest_ip) => {
            // let from = UdpHdr {
            //     source: src.port,
            //     dest: old_dest_port,
            //     len: u16::to_be(ip_common.data_length),
            //     check: 0,
            // };

            let to = UdpHdr {
                source: new_src_port,
                dest: dest.port,
                len: u16::to_be(ip_common.data_length - packet_size_reduction),
                check: 0,
            };

            udp_check = ohno!(
                ctx,
                funcs::bpf_csum_diff(
                    //&from as *const UdpHdr as *mut UdpHdr as *mut u32,
                    //core::mem::size_of::<UdpHdr>() as u32,
                    core::ptr::null_mut(),
                    0,
                    &to as *const UdpHdr as *mut UdpHdr as *mut u32,
                    core::mem::size_of::<UdpHdr>() as u32,
                    udp_check,
                )
            ) as u32;

            // If we're removing the token we need to load the original bytes
            // and do another diff
            // if packet_size_reduction > 0 {
            //     let mut from = [0u8; TOKEN_MAX];

            //     // bpf_csum_diff requires size % 4 == 0
            //     let tok_align_4 = {
            //         let rem = packet_size_reduction % 4;
            //         if rem > 0 {
            //             packet_size_reduction + 4 - rem
            //         } else {
            //             packet_size_reduction
            //         }
            //     };

            //     if funcs::bpf_xdp_load_bytes(
            //         ctx.ctx,
            //         (EthHdr::LEN + Ipv6Hdr::LEN + ip_common.data_length as usize
            //             - packet_size_reduction as usize) as u32,
            //         &mut from as *mut u8 as *mut _,
            //         packet_size_reduction as _,
            //     ) != 0
            //     {
            //         return Err(());
            //     }

            //     log::warn!(
            //         ctx,
            //         "to remove {}, align {}, bytes {:x}, bytes all {:x}",
            //         packet_size_reduction,
            //         tok_align_4,
            //         &from[..packet_size_reduction as usize],
            //         &from[..],
            //     );

            //     udp_check = ohno!(
            //         ctx,
            //         funcs::bpf_csum_diff(
            //             &mut from as *mut u8 as *mut u32,
            //             tok_align_4 as _,
            //             core::ptr::null_mut(),
            //             0,
            //             udp_check,
            //         )
            //     ) as u32;
            // }

            const BLOCK_SIZE: usize = 256;

            let mut length = (ip_common.data_length - packet_size_reduction) as usize - UdpHdr::LEN;

            let mut block = [0u8; BLOCK_SIZE];
            let mut offset = EthHdr::LEN + Ipv6Hdr::LEN + UdpHdr::LEN;

            if length > 1500 {
                return Err(());
            }

            while length >= BLOCK_SIZE {
                if funcs::bpf_xdp_load_bytes(
                    ctx.ctx,
                    offset as _,
                    block.as_mut_ptr() as *mut _,
                    BLOCK_SIZE as _,
                ) != 0
                {
                    return Err(());
                }

                udp_check = ohno!(
                    ctx,
                    funcs::bpf_csum_diff(
                        core::ptr::null_mut(),
                        0,
                        block.as_mut_ptr() as *mut _,
                        BLOCK_SIZE as _,
                        udp_check,
                    )
                ) as u32;

                length -= BLOCK_SIZE;
                offset += BLOCK_SIZE;
            }

            if length > 0 && length < BLOCK_SIZE {
                let rem = length % 4;

                let align4_len = if rem > 0 {
                    let align4_len = length + 4 - rem;

                    // We need to do this redundant check otherwise the verifier will
                    // reject since it can't tell that length + 4 - rem will never exceed
                    // BLOCK_SIZE
                    if align4_len > BLOCK_SIZE {
                        return Err(());
                    }
                    block.as_mut_ptr().write_bytes(0, align4_len);
                    align4_len
                } else {
                    length
                };

                if funcs::bpf_xdp_load_bytes(
                    ctx.ctx,
                    offset as _,
                    block.as_mut_ptr() as *mut _,
                    length as _,
                ) != 0
                {
                    return Err(());
                }

                udp_check = ohno!(
                    ctx,
                    funcs::bpf_csum_diff(
                        core::ptr::null_mut(),
                        0,
                        block.as_mut_ptr() as *mut u32,
                        align4_len as _,
                        udp_check,
                    )
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
    udp_hdr.len = u16::to_be(ip_common.data_length - packet_size_reduction);

    if udp_check != 0 {
        let check = fold_checksum(udp_check);
        udp_hdr.check = if check != 0 { check } else { 0xffff };
    } else {
        udp_hdr.check = 0;
    }

    Ok(())
}

/// Finalizes the checksum computation
#[inline]
fn fold_checksum(mut csum: u32) -> u16 {
    csum += 0xffff;

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

/// Computes the IPv4 header checksum
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
