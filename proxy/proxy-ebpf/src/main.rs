#![no_std]
#![no_main]

// References:
// https://stackoverflow.com/questions/74144705/forward-http-requests-to-another-webserver-port-bpf-xdp
// https://github.com/cilium/cilium/blob/main/bpf/bpf_xdp.c
// https://fly.io/blog/bpf-xdp-packet-filters-and-udp/
// https://konghq.com/blog/engineering/writing-an-ebpf-xdp-load-balancer-in-rust
// https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::net;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn proxy(ctx: XdpContext) -> u32 {
    match try_proxy(ctx) {
        Ok(ret) => ret,
        Err(_ret) => xdp_action::XDP_PASS,
    }
}

fn try_proxy(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    let src_addr = match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

            match unsafe { (*ipv4hdr).proto } {
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                    net::SocketAddr::V4(net::SocketAddrV4::new(src_addr, u16::from_be(unsafe { (*udphdr).source })))
                }
                _ => return Err(()),
            }
        }
        EtherType::Ipv6 => {
            return Err(());
            // let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            // let src_addr = u32::from_be(unsafe { (*ipv6hdr).src_addr });

            // match unsafe { (*ipv4hdr).proto } {
            //     IpProto::Udp => {
            //         let udphdr: *const UdpHdr =
            //             ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            //         net::SocketAddr::V4(net::SocketAddrV4::new(src_addr, u16::from_be(unsafe { (*udphdr).source })))
            //     }
            //     _ => return Err(()),
            // }
        }
    };

    


    info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
