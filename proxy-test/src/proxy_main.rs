use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;

enum Subcommand {
    Test,
    Run,
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp5s0")]
    iface: String,
    cmd: Subcommand,
}

#[cfg(debug_assertions)]
const PROG: &[u8] = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/proxy");

#[cfg(not(debug_assertions))]
const PROG: &[u8] = include_bytes_aligned!("../../target/bpfel-unknown-none/release/proxy");

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    // let rlim = libc::rlimit {
    //     rlim_cur: libc::RLIM_INFINITY,
    //     rlim_max: libc::RLIM_INFINITY,
    // };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    // if ret != 0 {
    //     debug!("remove limit on locked memory failed, ret is: {}", ret);
    // }

    
    let mut bpf = aya::BpfLoader::new()
        .btf(aya::Btf::from_sys_fs().ok().as_ref())
        .set_global("TOKEN_SIZE", &16, true)
        .load(PROG)?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        log::warn!("failed to initialize eBPF logger: {e}", e);
    }
    let program: &mut Xdp = bpf.program_mut("proxy").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    log::info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    log::info!("Exiting...");

    Ok(())
}
