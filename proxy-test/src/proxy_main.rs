use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use serde::{Deserialize, Deserializer};
use std::net::{Ipv6Addr, SocketAddr};
use tokio::signal;

#[derive(clap::Subcommand, Copy, Clone)]
enum Subcommand {
    Proxy,
    Tester,
}

#[derive(Parser)]
struct Opt {
    #[command(subcommand)]
    cmd: Subcommand,
}

struct Endpoint {
    addr: SocketAddr,
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str_addr = String::deserialize(deserializer)?;
        Ok(Self {
            addr: str_addr.parse().map_err(serde::de::Error::custom)?,
        })
    }
}

impl Endpoint {
    fn token(&self, buf: &mut [u8]) {
        use std::hash::{Hash, Hasher as _};

        let mut hasher = proxy_common::fnv::hasher();
        self.addr.hash(&mut hasher);
        let hash = hasher.finish();
        let hash_bytes = hash.to_le_bytes();

        buf.copy_from_slice(&hash_bytes[..buf.len()]);
    }
}

fn iface() -> String {
    "enp5s0".into()
}

#[derive(Deserialize)]
struct ProxyConfig {
    #[serde(default = "iface")]
    iface: String,
    port: u16,
}

#[derive(Deserialize)]
struct TesterConfig {
    proxy: Vec<Endpoint>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    token_length: u8,
    proxy: ProxyConfig,
    tester: TesterConfig,
    servers: Vec<Endpoint>,
}

// For some reason I don't feel like debugging local_ip_address fails to get the ipv6 address
// of the host, so just fallback to retrieving it from the file system
fn local_ipv6() -> anyhow::Result<std::net::IpAddr> {
    let iface = std::fs::read_to_string("/proc/net/if_inet6")
        .context("failed to read /proc/net/if_inet6")?;

    for line in iface.lines() {
        let mut items = line.split(' ').rev();

        // The last item is the interface name, ignore it if it is the loopback or tailscale
        // interface, which will be fine unless the host has multiple active network interfaces
        let Some(iface_name) = items.next() else {
            continue;
        };
        let iface_name = iface_name.trim();

        if iface_name == "lo" || iface_name.starts_with("tailscale") {
            tracing::debug!("skipping interface {iface_name}");
            continue;
        }

        let Some(addr) = items.last() else {
            continue;
        };
        if addr.len() != 32 {
            tracing::debug!("skipping malformed ipv6 address {addr} for {iface_name}");
            continue;
        }

        let mut parts = [0u16; 8];

        for (chunk, part) in addr.as_bytes().chunks_exact(4).zip(parts.iter_mut()) {
            *part = u16::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
        }

        return Ok(std::net::IpAddr::V6(Ipv6Addr::new(
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7],
        )));
    }

    anyhow::bail!("unable to locate active ipv6 interface");
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if let Err(err) = real_main().await {
        tracing::error!("{err:#}");
    }

    Ok(())
}

async fn real_main() -> Result<(), anyhow::Error> {
    use tracing_subscriber::prelude::*;
    let opt = Opt::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg: Config = {
        let toml = std::fs::read_to_string("config.toml").context("failed to read config.toml")?;
        toml::from_str(&toml).context("failed to parse config.toml")?
    };

    let servers = spawn_servers(&cfg)
        .await
        .context("failed to spawn udp echo server(s)")?;

    match opt.cmd {
        Subcommand::Proxy => run_proxy(cfg).await?,
        Subcommand::Tester => run_tester(cfg).await?,
    }

    servers.abort();
    Ok(())
}

async fn spawn_servers(cfg: &Config) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let ipv4 = local_ip_address::local_ip().context("failed to get ipv4 address")?;
    let ipv6 = local_ipv6().context("failed to get ipv6 address")?;

    let mut servers = Vec::new();
    for ep in &cfg.servers {
        let ip = dbg!(ep.addr.ip());
        if ip != ipv4 && ip != ipv6 {
            tracing::debug!("address mismatch {ip}");
            continue;
        }

        let res = if dbg!(ip).is_ipv4() {
            tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, ep.addr.port())).await
        } else {
            tokio::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, ep.addr.port())).await
        };

        let socket = res.with_context(|| format!("unable to bind {:?}", ep.addr))?;
        tracing::info!("bound {}", socket.local_addr().unwrap());
        servers.push(socket);
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    let len = servers.len();
    let jh = tokio::spawn(async move {
        let mut set = tokio::task::JoinSet::<anyhow::Result<()>>::new();

        for server in servers {
            let tx = tx.clone();
            set.spawn(async move {
                let mut buf = [0u8; 128];
                let addr = server.local_addr().unwrap();
                tracing::info!("UDP echo running {addr}");
                tx.send(()).await.expect("rx dropped");

                loop {
                    let (read, addr) = server
                        .recv_from(&mut buf)
                        .await
                        .with_context(|| format!("{addr} failed to recv"))?;

                    tracing::info!("echoing {read} bytes to {addr}");

                    server
                        .send_to(&buf[..read], addr)
                        .await
                        .with_context(|| format!("{addr} failed to send"))?;
                }
            });
        }

        set.join_all().await;
    });

    for _ in 0..len {
        rx.recv().await.expect("senders dropped");
    }

    Ok(jh)
}

async fn run_proxy(cfg: Config) -> anyhow::Result<()> {
    use std::net::IpAddr;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        tracing::debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let _ipv4 = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, cfg.proxy.port))
        .context("failed to bind ipv4 socket");
    let _ipv6 = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, cfg.proxy.port))
        .context("failed to bind ipv6 socket");

    let mut loader = aya::EbpfLoader::new();
    //loader.btf(aya::Btf::from_sys_fs().ok().as_ref());
    let tok_size = cfg.token_length as u64;
    loader.set_global("TOKEN_SIZE", &tok_size, true);

    let port = u16::to_be(cfg.proxy.port);
    loader.set_global("EXTERNAL_PORT", &port, true);

    let ipv4 = local_ip_address::local_ip().context("failed to get ipv4 address")?;
    let ipv6 = local_ipv6().context("failed to get ipv6 address")?;

    let IpAddr::V4(v4) = ipv4 else { unreachable!() };
    let ipv4 = v4.to_bits().to_be();
    loader.set_global("SRC_IPV4", &ipv4, true);

    let IpAddr::V6(v6) = ipv6 else { unreachable!() };
    let ipv6 = v6.octets();
    loader.set_global("SRC_IPV6", &ipv6, true);

    let path = if cfg!(debug_assertions) {
        "target/bpfel-unknown-none/debug/proxy"
    } else {
        "target/bpfel-unknown-none/release/proxy"
    };

    let ebpf_byte_code =
        std::fs::read(path).with_context(|| format!("failed to read eBPF bytecode from {path}"))?;

    let mut bpf = loader.load(&ebpf_byte_code)?;

    let mut ep_map = aya::maps::HashMap::try_from(
        bpf.map_mut("TARGET_ENDPOINTS")
            .context("failed to retrieve TARGET_ENDPOINTS map")?,
    )?;

    let mut tok = vec![0u8; cfg.token_length as usize];

    for ep in &cfg.servers {
        ep.token(&mut tok);
        let tok_hash = proxy_common::fnv::hash(&tok);

        tracing::info!("hash for {}: {tok_hash}", ep.addr);

        ep_map
            .insert(
                tok_hash,
                proxy_common::SockAddrEntry {
                    addr: proxy_common::SockAddr {
                        ip: match ep.addr {
                            SocketAddr::V4(v4) => {
                                proxy_common::IpAddr::V4(v4.ip().to_bits().to_be())
                            }
                            SocketAddr::V6(v6) => proxy_common::IpAddr::V6(v6.ip().octets()),
                        },
                        port: u16::to_be(ep.addr.port()),
                    },
                },
                0,
            )
            .with_context(|| format!("failed to insert server endpoint: {:?}", ep.addr))?;
    }

    let mut q_map = aya::maps::Queue::try_from(
        bpf.map_mut("PORT_QUEUE")
            .context("failed to retrieve PORT_QUEUE map")?,
    )?;

    for port in [7778u16, 7779, 9002, 9003] {
        q_map
            .push(u16::to_be(port), 0)
            .with_context(|| format!("failed to push port: {port}"))?;
    }

    if let Err(e) = aya_log::BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        tracing::warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut Xdp = bpf.program_mut("proxy").unwrap().try_into()?;
    program.load()?;
    program.attach(&cfg.proxy.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    tracing::info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    tracing::info!("Exiting proxy...");

    Ok(())
}

async fn run_tester(cfg: Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(cfg.tester.proxy.len(), 1 | 2),
        "only 1 proxy endpoint (ipv4 and/or ipv6) is supported"
    );

    let mut clients = Vec::with_capacity(cfg.tester.proxy.len());

    for proxy in cfg.tester.proxy {
        if proxy.addr.is_ipv4() {
            clients.push((
                tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
                    .await
                    .context("failed to bind ipv4 client socket")?,
                proxy.addr,
            ));
        } else {
            clients.push((
                tokio::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))
                    .await
                    .context("failed to bind ipv6 client socket")?,
                proxy.addr,
            ));
        }
    }

    let mut counter = 1u32;

    let mut send_buf = vec![0u8; 4 + cfg.token_length as usize];
    let mut recv_buf = [0u8; 5];

    for server in cfg.servers {
        server.token(&mut send_buf[4..]);

        for (socket, remote_addr) in &clients {
            let local = socket.local_addr().unwrap();
            tracing::info!("{counter} {local} -> {remote_addr}",);

            send_buf[..4].copy_from_slice(&counter.to_le_bytes());
            if let Err(err) = socket.send_to(&send_buf, remote_addr).await {
                tracing::error!("{local} -> {remote_addr} - {err:#}");
                continue;
            }

            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                socket.recv_from(&mut recv_buf),
            )
            .await
            {
                Ok(res) => match res {
                    Ok((received, addr)) => {
                        if addr != *remote_addr {
                            tracing::error!("{local} <- {addr} invalid remote peer");
                        }

                        if received != 4 {
                            tracing::error!("{local} <- {addr} invalid length {received}");
                        } else if &recv_buf[..4] != &send_buf[..4] {
                            tracing::error!(
                                "{local} <- {addr}, expected {:?}, got {:?}",
                                &send_buf[..4],
                                &recv_buf[..4],
                            );
                        }

                        tracing::info!("received {counter} packet from {addr}");
                    }
                    Err(err) => {
                        tracing::error!("recv_from failed {local} - {err:#}",);
                    }
                },
                Err(_) => {
                    tracing::error!("timed out waiting for reply {counter} from {remote_addr:?}");
                }
            }

            counter += 1;
        }
    }

    tracing::info!("Exiting tester...");

    Ok(())
}
