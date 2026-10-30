# libmeow

Android JNI bridge for the [meow-rs](https://github.com/meow-rs/meow-rs) proxy
kernel — the `libmeow.so` that AsteriskMEOW loads instead of mihomo's
`libclash`.

Status: **milestone 1 (VPN TUN data path)**. This is not a Libclash-compatible
API yet; it exposes only what the PoC app needs:

```java
Libmeow.nativeInit();
Libmeow.nativeSetHomeDir(dir);                   // meow resource home
Libmeow.nativeSetProtector(vpnService);          // VpnService.protect(fd)
Libmeow.nativeSetOwnerResolver(vpnService);      // flow uid/package
Libmeow.nativeSetProtectorCallback(tunInterface); // mihomo TunInterface.markSocket
Libmeow.nativeSetOwnerCallback(tunInterface);     // TunInterface.querySocketUid
Libmeow.nativeStart(configPath, tunFd, mtu);     // engine + TUN
Libmeow.nativeStop();
Libmeow.nativeIsRunning();
Libmeow.nativeUploadTotal(); / nativeDownloadTotal();
Libmeow.nativeVersion(); / nativeLastError();
```

## What is patched

`third_party/meow-rs` is meow-rs **v0.28.0** (git submodule) with a small
Android patch in `patches/0001-tun-fd-android.patch`:

1. `TunListenerConfig.fd` — the TUN listener can adopt a pre-opened device
   descriptor (`VpnService.Builder.establish()`) through
   `tun_rs::AsyncDevice::from_fd`, instead of creating a desktop device with
   `tun_rs::DeviceBuilder`. Android's `VpnService` owns addresses, routes and
   DNS; `auto_route`/`RouteGuard` are no-ops there.
2. `route_manager` is gated to non-Android targets (it has no Android
   backend); Android gets a no-op `RouteGuard`.
3. `meow-api`'s `TunListenerConfig` construction passes `fd: None` for the
   desktop path.

Everything else — config parsing, rules, DNS/fake-IP, lwIP netstack, TCP/UDP
flows, routing — is upstream meow-rs.

Apply the patch to a fresh submodule with:

```bash
git submodule update --init third_party/meow-rs
git -C third_party/meow-rs checkout v0.28.0
git -C third_party/meow-rs apply ../../patches/0001-tun-fd-android.patch
```

## Build

Prereqs: Rust with the Android targets, NDK r30, SDK CMake 3.22.1,
`cargo-ndk`.

```bash
rustup target add aarch64-linux-android --toolchain 1.95.0
./scripts/build-android.sh arm64-v8a release
# -> build/jniLibs/arm64-v8a/libmeow.so
```

`BORING_BSSL_RUST_CPPLIB=c++_static` and a per-target
`CMAKE_TOOLCHAIN_FILE_<triple>` are required (see the script); meow links
BoringSSL, and the NDK's default `libc++_shared.so` is not packaged by the
app.

## Verified

Built and run on alioth (Android 16, arm64): the VpnService fd is adopted by
meow's TUN listener, DNS resolves through fake-IP, `adb shell curl
http://example.com/` returns 200 through the tunnel, `UID` rules match via
`getConnectionOwnerUid`, a SOCKS5 proxy carries traffic with no DIRECT
fallback, and stop removes the interface. The AsteriskMEOW META-UI APK runs
the same library through its `libclash` shim. Details:
AsteriskMEOW/meow-poc/VERIFICATION.md.

## License

MIT. meow-rs is MIT; `meow-lwip` vendors the madeye lwIP fork
(MIT/Apache-2.0 + BSD-3-Clause C sources).
