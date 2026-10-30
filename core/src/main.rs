//! ROOT/TUN core for AsteriskMEOW.
//!
//! asteriskd starts this PIE with `-d <workdir> -f <config>` and waits for
//! the named TUN interface. META's config describes the TUN listener under
//! `listeners: type: tun`; meow instead consumes a top-level `tun:` block,
//! so this binary reshapes the YAML, creates `/dev/net/tun` itself, hands the
//! fd to meow's TUN listener, and installs the policy routes asteriskd would
//! otherwise expect the core to own.

use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use meow_listener::{TunListener, TunListenerConfig, TunReady, TunRouteScope};
use meow_tunnel::Tunnel;
use serde_yaml::{Mapping, Value};

const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const RULE_PREF_CORE: &str = "100";
const RULE_PREF_TUN: &str = "200";
const TUN_TABLE: &str = "2022";

fn main() {
    if let Err(error) = run() {
        eprintln!("meow-core: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    let doc = std::fs::read_to_string(&args.config)
        .map_err(|e| format!("read {}: {e}", args.config.display()))?;
    let (yaml, tun) = reshape(&doc)?;
    let shaped = Path::new(&args.workdir).join("config.meow-core.yaml");
    std::fs::write(&shaped, yaml).map_err(|e| format!("write {}: {e}", shaped.display()))?;

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .ok();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio: {e}"))?;
    rt.block_on(async { run_engine(&args, &tun).await })
}

struct Args {
    workdir: PathBuf,
    config: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut workdir = PathBuf::from(".");
        let mut config = None;
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "-d" => workdir = PathBuf::from(it.next().ok_or("missing -d value")?),
                "-f" => config = Some(PathBuf::from(it.next().ok_or("missing -f value")?)),
                "-h" | "--help" => {
                    println!("usage: meow-core -d <workdir> -f <config>");
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(Self {
            workdir,
            config: config.ok_or("missing -f <config>")?,
        })
    }
}

struct TunSpec {
    device: String,
    mtu: u16,
    inet4: String,
    dns_hijack: bool,
}

fn reshape(source: &str) -> Result<(String, TunSpec), String> {
    let mut root: Value = serde_yaml::from_str(source).map_err(|e| format!("parse YAML: {e}"))?;
    let map = root.as_mapping_mut().ok_or("config root is not a mapping")?;

    let mut device = "asterisk0".to_string();
    let mut mtu = 1500u16;
    let mut inet4 = "172.19.0.1/30".to_string();
    let mut dns_hijack = true;

    if let Some(Value::Sequence(listeners)) = map.get_mut(Value::String("listeners".into())) {
        listeners.retain(|item| {
            let Some(listener) = item.as_mapping() else { return true };
            if listener.get(Value::String("type".into())).and_then(Value::as_str) != Some("tun") {
                return true;
            }
            if let Some(v) = listener.get(Value::String("device".into())).and_then(Value::as_str) {
                device = v.to_string();
            }
            if let Some(v) = listener.get(Value::String("mtu".into())).and_then(Value::as_u64) {
                mtu = v as u16;
            }
            if let Some(v) = listener.get(Value::String("inet4-address".into())) {
                if let Some(value) = first_string(v) {
                    inet4 = value;
                }
            }
            if let Some(v) = listener.get(Value::String("dns-hijack".into())) {
                dns_hijack = !matches!(v, Value::Sequence(s) if s.is_empty());
            }
            false
        });
        if listeners.is_empty() {
            map.remove(Value::String("listeners".into()));
        }
    }

    // META emits tun.enable:false because Mihomo's TUN listener owns the device;
    // meow needs the block enabled for config validation, while this process
    // still creates the fd itself.
    let mut tun = Mapping::new();
    tun.insert(Value::String("enable".into()), Value::Bool(true));
    tun.insert(Value::String("device".into()), Value::String(device.clone()));
    tun.insert(Value::String("mtu".into()), Value::Number(mtu.into()));
    tun.insert(Value::String("inet4-address".into()), Value::String(inet4.clone()));
    tun.insert(Value::String("auto-route".into()), Value::Bool(false));
    if dns_hijack {
        tun.insert(
            Value::String("dns-hijack".into()),
            Value::Sequence(vec![Value::String("0.0.0.0:53".into())]),
        );
    }
    map.insert(Value::String("tun".into()), Value::Mapping(tun));
    map.insert(Value::String("log-level".into()), Value::String("debug".into()));

    // meow's resolver rejects the literal `system`; META uses it for the
    // bootstrap nameserver.
    if let Some(dns) = map.get_mut(Value::String("dns".into())) {
        replace_system_nameservers(dns);
    }

    let yaml = serde_yaml::to_string(&root).map_err(|e| format!("serialize YAML: {e}"))?;
    Ok((
        yaml,
        TunSpec {
            device,
            mtu,
            inet4,
            dns_hijack,
        },
    ))
}

fn replace_system_nameservers(value: &mut Value) {
    match value {
        Value::String(text) if text == "system" => {
            *text = "223.5.5.5".to_string();
        }
        Value::Sequence(values) => {
            for value in values {
                replace_system_nameservers(value);
            }
        }
        Value::Mapping(map) => {
            for value in map.values_mut() {
                replace_system_nameservers(value);
            }
        }
        _ => {}
    }
}

fn first_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Sequence(s) => s.iter().find_map(Value::as_str).map(str::to_string),
        _ => None,
    }
}

async fn run_engine(args: &Args, tun: &TunSpec) -> Result<(), String> {
    meow_common::home_dir::set_home_dir(args.workdir.clone());
    meow_common::process_lookup::enable_inbound_process_info();
    let config = meow_config::load_config(
        args.workdir.join("config.meow-core.yaml").to_string_lossy().as_ref(),
    )
    .await
    .map_err(|e| format!("load config: {e:#}"))?;

    if config.dns.enabled {
        meow_common::set_host_resolver(Arc::new(
            meow_dns::ResolverHostHook::new_with_proxy_resolver(
                Arc::clone(&config.dns.resolver),
                config.dns.proxy_resolver.clone(),
            ),
        ));
    }

    let fd = create_tun(&tun.device)?;
    configure_interface(&tun.device, &tun.inet4, tun.mtu)?;
    let rules = PolicyRoutes::install(&tun.device)?;

    let tunnel = Tunnel::new_with_slot(config.dns.resolver_slot.clone());
    tunnel.set_mode(config.general.mode);
    tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
    tunnel.spawn_background_tasks();

    let cfg = TunListenerConfig {
        device: Some(tun.device.clone()),
        mtu: tun.mtu,
        inet4_address: tun.inet4.parse().map_err(|e| format!("inet4: {e}"))?,
        inet6_address: None,
        auto_route: false,
        route_scope: TunRouteScope::FakeIp,
        outbound_interface: None,
        dns_hijack: tun.dns_hijack,
        udp_timeout: Duration::from_secs(60),
        max_connections: 512,
        fd: Some(fd),
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        if let Err(error) = TunListener::new(tunnel, cfg, "tun".into())
            .with_readiness_signal(tx)
            .run()
            .await
        {
            eprintln!("meow-core: TUN listener exited: {error}");
        }
    });

    match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(TunReady::Ready { .. })) => eprintln!("meow-core: TUN ready on {}", tun.device),
        Ok(Ok(TunReady::Failed(error))) => return Err(format!("TUN readiness failed: {error}")),
        Ok(Err(error)) => return Err(format!("TUN readiness channel: {error}")),
        Err(_) => return Err("TUN readiness timed out".into()),
    }

    wait_for_signal().await;
    task.abort();
    drop(rules);
    Ok(())
}

fn create_tun(name: &str) -> Result<RawFd, String> {
    let path = if Path::new("/dev/net/tun").exists() {
        c"/dev/net/tun"
    } else {
        c"/dev/tun"
    };
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("open tun: {}", std::io::Error::last_os_error()));
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= ifr.ifr_name.len() {
        unsafe { libc::close(fd) };
        return Err("TUN name too long".into());
    }
    for (dst, src) in ifr.ifr_name.iter_mut().zip(bytes.iter().copied()) {
        *dst = src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("TUNSETIFF {name}: {error}"));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    Ok(fd)
}

fn configure_interface(device: &str, inet4: &str, mtu: u16) -> Result<(), String> {
    ip(&["addr", "replace", inet4, "dev", device])?;
    ip(&["link", "set", "dev", device, "mtu", &mtu.to_string(), "up"])?;
    Ok(())
}

struct PolicyRoutes {
    uplink_table: Option<String>,
}

impl PolicyRoutes {
    fn install(device: &str) -> Result<Self, String> {
        let uplink = default_uplink().and_then(|iface| {
            let table = iface.clone();
            ip(&["route", "show", "table", &table]).ok()?;
            Some(table)
        });
        let _ = ip(&["route", "replace", "default", "dev", device, "table", TUN_TABLE]);
        if let Some(table) = &uplink {
            let _ = ip(&[
                "rule", "add", "pref", RULE_PREF_CORE, "uidrange", "0-0", "lookup", table,
            ]);
        }
        let _ = ip(&["rule", "add", "pref", RULE_PREF_TUN, "lookup", TUN_TABLE]);
        Ok(Self { uplink_table: uplink })
    }
}

impl Drop for PolicyRoutes {
    fn drop(&mut self) {
        let _ = ip(&["rule", "del", "pref", RULE_PREF_TUN]);
        let _ = ip(&["rule", "del", "pref", RULE_PREF_CORE]);
        let _ = ip(&["route", "flush", "table", TUN_TABLE]);
        self.uplink_table.take();
    }
}

fn default_uplink() -> Option<String> {
    let output = Command::new("ip").args(["route", "get", "1.1.1.1"]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut words = text.split_whitespace();
    while let Some(word) = words.next() {
        if word == "dev" {
            return words.next().map(str::to_string);
        }
    }
    None
}

fn ip(args: &[&str]) -> Result<(), String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("ip {:?}: {e}", args))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

async fn wait_for_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = async { if let Some(signal) = term.as_mut() { signal.recv().await; } } => {},
    }
}
