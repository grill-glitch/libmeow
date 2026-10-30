//! libmeow — Android JNI bridge for the meow-rs kernel.
//!
//! Scope of this first milestone: start a meow engine from a Clash YAML
//! profile, adopt a `VpnService.Builder.establish()` fd into meow's TUN
//! listener (the fd patch lives in `third_party/meow-rs`), protect every
//! outbound socket through `VpnService.protect`, and expose traffic totals.
//!
//! The kernel is the real one: config parsing, rules, DNS, routing and the
//! lwIP netstack are all meow-rs. This crate only wires Android to it.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use meow_listener::{TunListener, TunListenerConfig, TunReady, TunRouteScope};
use meow_tunnel::Tunnel;

const VERSION: &str = concat!("libmeow ", env!("CARGO_PKG_VERSION"), " (meow-rs 0.28.0)");
const TUN_STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const TUN_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct EngineState {
    rt: tokio::runtime::Runtime,
    tunnel: Tunnel,
    tun_task: Option<tokio::task::JoinHandle<()>>,
    /// Flipped to true by the TUN listener once lwIP's global core has
    /// fully torn down. A successor stack must wait for it.
    core_done: Option<tokio::sync::watch::Receiver<bool>>,
}

static ENGINE: Mutex<Option<EngineState>> = Mutex::new(None);
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());
static LOGGER: OnceLock<()> = OnceLock::new();

fn set_error(msg: impl Into<String>) {
    let msg = msg.into();
    log::error!("{msg}");
    *LAST_ERROR.lock().unwrap() = msg;
}

fn init_logging() {
    LOGGER.get_or_init(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("libmeow"),
        );
        // meow emits `tracing` events; forward them to logcat.
        struct LogcatWriter;
        impl std::io::Write for LogcatWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let line = String::from_utf8_lossy(buf);
                let line = line.trim_end();
                if !line.is_empty() {
                    log::info!("{line}");
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let _ = tracing_subscriber::fmt()
            .with_writer(|| LogcatWriter)
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .try_init();
    });
}

fn stop_engine(mut state: EngineState) {
    if let Some(task) = state.tun_task.take() {
        task.abort();
        let _ = state.rt.block_on(async { task.await });
    }
    if let Some(mut done) = state.core_done.take() {
        let _ = state.rt.block_on(async {
            let _ = tokio::time::timeout(TUN_TEARDOWN_TIMEOUT, async {
                loop {
                    if *done.borrow() {
                        break;
                    }
                    if done.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
        });
    }
    state.rt.shutdown_timeout(TUN_TEARDOWN_TIMEOUT);
}

fn start_engine(config_path: &str, fd: i32, mtu: u16) -> Result<EngineState, String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    let built = rt.block_on(async {
        // UID / PROCESS-NAME rules are dead on Android unless the inbound
        // declares that it fills the owner fields; the TUN listener does via
        // the inbound-owner hook installed by nativeSetOwnerResolver.
        meow_common::process_lookup::enable_inbound_process_info();

        let config = meow_config::load_config(config_path)
            .await
            .map_err(|e| format!("load config {config_path}: {e:#}"))?;

        if config.dns.enabled {
            meow_common::set_host_resolver(Arc::new(
                meow_dns::ResolverHostHook::new_with_proxy_resolver(
                    Arc::clone(&config.dns.resolver),
                    config.dns.proxy_resolver.clone(),
                ),
            ));
        }

        let tunnel = Tunnel::new_with_slot(config.dns.resolver_slot.clone());
        tunnel.set_mode(config.general.mode);
        tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
        tunnel.spawn_background_tasks();

        let tun_cfg = TunListenerConfig {
            device: Some("meow".into()),
            mtu,
            inet4_address: "172.19.0.1/30"
                .parse()
                .map_err(|e| format!("tun address: {e}"))?,
            inet6_address: None,
            // VpnService owns the device's addresses, routes and DNS.
            auto_route: false,
            route_scope: TunRouteScope::FakeIp,
            outbound_interface: None,
            dns_hijack: true,
            udp_timeout: Duration::from_secs(60),
            max_connections: 256,
            fd: Some(fd),
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let tun_tunnel = tunnel.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = TunListener::new(tun_tunnel, tun_cfg, "tun".into())
                .with_readiness_signal(tx)
                .run()
                .await
            {
                log::error!("TUN listener exited: {e}");
            }
        });

        let ready = match tokio::time::timeout(TUN_STARTUP_TIMEOUT, rx).await {
            Ok(Ok(ready)) => ready,
            Ok(Err(e)) => {
                task.abort();
                return Err(format!("TUN readiness channel closed: {e}"));
            }
            Err(_) => {
                task.abort();
                return Err(format!(
                    "TUN startup timed out after {}s",
                    TUN_STARTUP_TIMEOUT.as_secs()
                ));
            }
        };

        match ready {
            TunReady::Ready { core_done, .. } => Ok((tunnel, task, core_done)),
            TunReady::Failed(e) => {
                task.abort();
                Err(format!("TUN startup failed: {e}"))
            }
        }
    })?;

    let (tunnel, tun_task, core_done) = built;
    Ok(EngineState {
        rt,
        tunnel,
        tun_task: Some(tun_task),
        core_done: Some(core_done),
    })
}

// ─── JNI surface ──────────────────────────────────────────────────────────

/// `Libmeow.nativeInit()` — install logcat logging. Idempotent.
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeInit(
    _env: JNIEnv,
    _class: JClass,
) {
    init_logging();
}

/// `Libmeow.nativeVersion(): String`
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    env.new_string(VERSION)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// `Libmeow.nativeStart(configPath: String, fd: Int, mtu: Int): Int`
///
/// Starts the kernel and the TUN listener on an already-established
/// VpnService fd. Ownership of `fd` transfers to the listener. Returns 0
/// on success; -1 on failure (see `nativeLastError`).
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    fd: jint,
    mtu: jint,
) -> jint {
    init_logging();
    let path: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(e) => {
            set_error(format!("config path: {e}"));
            return -1;
        }
    };
    if fd < 0 {
        set_error("invalid TUN fd");
        return -1;
    }
    let mtu = if mtu <= 0 { 1500 } else { mtu as u16 };

    let mut guard = ENGINE.lock().unwrap();
    if let Some(old) = guard.take() {
        stop_engine(old);
    }
    match start_engine(&path, fd, mtu) {
        Ok(state) => {
            log::info!("engine started: {path} (fd={fd}, mtu={mtu})");
            *guard = Some(state);
            0
        }
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// `Libmeow.nativeStop()` — stop the TUN listener and drop the kernel.
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) {
    let state = ENGINE.lock().unwrap().take();
    if let Some(state) = state {
        stop_engine(state);
        log::info!("engine stopped");
    }
}

/// `Libmeow.nativeIsRunning(): Boolean`
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeIsRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if ENGINE.lock().unwrap().is_some() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

fn traffic() -> (i64, i64) {
    let guard = ENGINE.lock().unwrap();
    match guard.as_ref() {
        Some(state) => {
            let (up, down) = state.tunnel.statistics().snapshot();
            (up as i64, down as i64)
        }
        None => (0, 0),
    }
}

/// `Libmeow.nativeUploadTotal(): Long`
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeUploadTotal(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    traffic().0
}

/// `Libmeow.nativeDownloadTotal(): Long`
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeDownloadTotal(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    traffic().1
}

/// `Libmeow.nativeLastError(): String`
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeLastError(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let msg = LAST_ERROR.lock().unwrap().clone();
    env.new_string(msg)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// `Libmeow.nativeSetProtector(service: VpnService)` — every outbound
/// socket meow opens calls `service.protect(fd)` before connect/bind.
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeSetProtector(
    mut env: JNIEnv,
    _class: JClass,
    service: JObject,
) {
    #[cfg(target_os = "android")]
    {
        match protect::install(&mut env, service) {
            Ok(()) => log::info!("VpnService.protect hook installed"),
            Err(e) => set_error(format!("install protect hook: {e}")),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (&mut env, service);
        log::warn!("nativeSetProtector is a no-op outside Android");
    }
}

/// `Libmeow.nativeClearProtector()`
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeClearProtector(
    _env: JNIEnv,
    _class: JClass,
) {
    #[cfg(target_os = "android")]
    meow_common::clear_socket_protector();
}

/// `Libmeow.nativeSetOwnerResolver(service: VpnService)` — per-flow
/// `ConnectivityManager.getConnectionOwnerUid` lookup for UID/PROCESS-NAME
/// rules.
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeSetOwnerResolver(
    mut env: JNIEnv,
    _class: JClass,
    service: JObject,
) {
    #[cfg(target_os = "android")]
    {
        match owner::install(&mut env, service) {
            Ok(()) => log::info!("getConnectionOwnerUid hook installed"),
            Err(e) => set_error(format!("install owner hook: {e}")),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (&mut env, service);
    }
}

#[cfg(target_os = "android")]
mod protect {
    use std::io;
    use std::sync::Arc;

    use jni::objects::{GlobalRef, JObject, JValue};
    use jni::{JNIEnv, JavaVM};

    use meow_common::SocketProtector;

    pub struct VpnProtector {
        vm: JavaVM,
        service: GlobalRef,
    }

    impl SocketProtector for VpnProtector {
        fn protect(&self, fd: std::os::fd::RawFd) -> io::Result<()> {
            let mut env = self.vm.attach_current_thread().map_err(|e| {
                io::Error::other(format!("attach to JVM: {e}"))
            })?;
            let ok = env
                .call_method(
                    self.service.as_obj(),
                    "protect",
                    "(I)Z",
                    &[JValue::Int(fd)],
                )
                .and_then(|v| v.z())
                .map_err(|e| io::Error::other(format!("VpnService.protect: {e}")))?;
            if ok {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "VpnService.protect returned false",
                ))
            }
        }
    }

    pub fn install(env: &mut JNIEnv, service: JObject) -> Result<(), String> {
        let vm = env.get_java_vm().map_err(|e| e.to_string())?;
        let service = env
            .new_global_ref(service)
            .map_err(|e| format!("global ref: {e}"))?;
        meow_common::set_socket_protector(Arc::new(VpnProtector { vm, service }));
        Ok(())
    }
}

#[cfg(target_os = "android")]
mod owner {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use jni::objects::{GlobalRef, JObject, JString, JValue};
    use jni::{JNIEnv, JavaVM};

    use meow_common::inbound_owner::{InboundOwner, InboundOwnerResolver};
    use meow_common::Network;

    pub struct AndroidOwner {
        vm: JavaVM,
        connectivity: GlobalRef,
        package_manager: GlobalRef,
    }

    impl InboundOwnerResolver for AndroidOwner {
        fn lookup(
            &self,
            network: Network,
            local: SocketAddr,
            remote: SocketAddr,
        ) -> Option<InboundOwner> {
            let mut env = self.vm.attach_current_thread().ok()?;
            let l = socket_addr(&mut env, local).ok()?;
            let r = socket_addr(&mut env, remote).ok()?;
            let protocol = if network == Network::Tcp { 6 } else { 17 };
            let uid = env
                .call_method(
                    self.connectivity.as_obj(),
                    "getConnectionOwnerUid",
                    "(ILjava/net/InetSocketAddress;Ljava/net/InetSocketAddress;)I",
                    &[JValue::Int(protocol), JValue::Object(&l), JValue::Object(&r)],
                )
                .ok()?
                .i()
                .ok()?;
            if uid < 0 {
                return None;
            }
            let name = env
                .call_method(
                    self.package_manager.as_obj(),
                    "getNameForUid",
                    "(I)Ljava/lang/String;",
                    &[JValue::Int(uid)],
                )
                .ok()?
                .l()
                .ok()?;
            let package = if name.is_null() {
                String::new()
            } else {
                let js = JString::from(name);
                env.get_string(&js).map(String::from).unwrap_or_default()
            };
            Some(InboundOwner {
                uid: uid as u32,
                package,
            })
        }
    }

    fn socket_addr<'a>(
        env: &mut JNIEnv<'a>,
        addr: SocketAddr,
    ) -> jni::errors::Result<JObject<'a>> {
        let host = env.new_string(addr.ip().to_string())?;
        env.new_object(
            "java/net/InetSocketAddress",
            "(Ljava/lang/String;I)V",
            &[JValue::Object(&host), JValue::Int(i32::from(addr.port()))],
        )
    }

    pub fn install(env: &mut JNIEnv, service: JObject) -> Result<(), String> {
        let vm = env.get_java_vm().map_err(|e| e.to_string())?;
        let connectivity_name = env
            .new_string("connectivity")
            .map_err(|e| e.to_string())?;
        let connectivity = env
            .call_method(
                &service,
                "getSystemService",
                "(Ljava/lang/String;)Ljava/lang/Object;",
                &[JValue::Object(&connectivity_name)],
            )
            .and_then(|v| v.l())
            .map_err(|e| format!("getSystemService: {e}"))?;
        let package_manager = env
            .call_method(
                &service,
                "getPackageManager",
                "()Landroid/content/pm/PackageManager;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| format!("getPackageManager: {e}"))?;
        let connectivity = env
            .new_global_ref(connectivity)
            .map_err(|e| e.to_string())?;
        let package_manager = env
            .new_global_ref(package_manager)
            .map_err(|e| e.to_string())?;
        meow_common::inbound_owner::set_inbound_owner_resolver(Arc::new(AndroidOwner {
            vm,
            connectivity,
            package_manager,
        }));
        Ok(())
    }
}

#[cfg(target_os = "android")]
mod protect_iface {
    use std::io;
    use std::sync::Arc;

    use jni::objects::{GlobalRef, JObject, JValue};
    use jni::{JNIEnv, JavaVM};

    use meow_common::SocketProtector;

    pub struct TunProtector {
        vm: JavaVM,
        iface: GlobalRef,
    }

    impl SocketProtector for TunProtector {
        fn protect(&self, fd: std::os::fd::RawFd) -> io::Result<()> {
            let mut env = self
                .vm
                .attach_current_thread()
                .map_err(|e| io::Error::other(format!("attach to JVM: {e}")))?;
            env.call_method(
                self.iface.as_obj(),
                "markSocket",
                "(I)V",
                &[JValue::Int(fd)],
            )
            .map_err(|e| io::Error::other(format!("TunInterface.markSocket: {e}")))?;
            Ok(())
        }
    }

    pub fn install(env: &mut JNIEnv, iface: JObject) -> Result<(), String> {
        let vm = env.get_java_vm().map_err(|e| e.to_string())?;
        let iface = env
            .new_global_ref(iface)
            .map_err(|e| format!("global ref: {e}"))?;
        meow_common::set_socket_protector(Arc::new(TunProtector { vm, iface }));
        Ok(())
    }
}

#[cfg(target_os = "android")]
mod owner_iface {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use jni::objects::{GlobalRef, JObject, JValue};
    use jni::{JNIEnv, JavaVM};

    use meow_common::inbound_owner::{InboundOwner, InboundOwnerResolver};
    use meow_common::Network;

    pub struct TunOwner {
        vm: JavaVM,
        iface: GlobalRef,
    }

    impl InboundOwnerResolver for TunOwner {
        fn lookup(
            &self,
            network: Network,
            local: SocketAddr,
            remote: SocketAddr,
        ) -> Option<InboundOwner> {
            let mut env = self.vm.attach_current_thread().ok()?;
            let l = env.new_string(local.to_string()).ok()?;
            let r = env.new_string(remote.to_string()).ok()?;
            let protocol = if network == Network::Tcp { 6 } else { 17 };
            let uid = env
                .call_method(
                    self.iface.as_obj(),
                    "querySocketUid",
                    "(ILjava/lang/String;Ljava/lang/String;)I",
                    &[JValue::Int(protocol), JValue::Object(&l), JValue::Object(&r)],
                )
                .ok()?
                .i()
                .ok()?;
            if uid < 0 {
                None
            } else {
                Some(InboundOwner {
                    uid: uid as u32,
                    package: String::new(),
                })
            }
        }
    }

    pub fn install(env: &mut JNIEnv, iface: JObject) -> Result<(), String> {
        let vm = env.get_java_vm().map_err(|e| e.to_string())?;
        let iface = env
            .new_global_ref(iface)
            .map_err(|e| format!("global ref: {e}"))?;
        meow_common::inbound_owner::set_inbound_owner_resolver(Arc::new(TunOwner { vm, iface }));
        Ok(())
    }
}

/// `Libmeow.nativeSetProtectorCallback(TunInterface)` — call `markSocket(fd)`
/// before every outbound connect/bind, matching mihomo's `TunInterface`.
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeSetProtectorCallback(
    mut env: JNIEnv,
    _class: JClass,
    iface: JObject,
) {
    #[cfg(target_os = "android")]
    {
        match protect_iface::install(&mut env, iface) {
            Ok(()) => log::info!("TunInterface.markSocket hook installed"),
            Err(e) => set_error(format!("install TunInterface protector: {e}")),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (&mut env, iface);
    }
}

/// `Libmeow.nativeSetOwnerCallback(TunInterface)` — call
/// `querySocketUid(protocol, src, dst)` per flow.
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeSetOwnerCallback(
    mut env: JNIEnv,
    _class: JClass,
    iface: JObject,
) {
    #[cfg(target_os = "android")]
    {
        match owner_iface::install(&mut env, iface) {
            Ok(()) => log::info!("TunInterface.querySocketUid hook installed"),
            Err(e) => set_error(format!("install TunInterface owner: {e}")),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (&mut env, iface);
    }
}

/// `Libmeow.nativeSetHomeDir(dir)` — meow's resource home (`Country.mmdb`,
/// `geosite.dat`, provider caches). Must be called before the first config
/// load; the app's `files/clash` directory is writable.
#[no_mangle]
pub extern "system" fn Java_org_asterisk_meow_Libmeow_nativeSetHomeDir(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) {
    if let Ok(dir) = env.get_string(&dir) {
        let dir: String = dir.into();
        meow_common::home_dir::set_home_dir(std::path::PathBuf::from(dir));
    }
}
