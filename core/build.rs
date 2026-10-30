use std::env;
use std::path::PathBuf;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android") {
        return;
    }

    // BoringSSL's static archives arrive through boring-sys's rlib. What the
    // cdylib link line lacks is the C++ ABI runtime: __gxx_personality_v0
    // and __cxa_* stay undefined even though boring-sys emits
    // `-lc++_static`, so dlopen fails with "cannot locate symbol".
    // Link libc++abi.a explicitly after the Rust objects.
    if let Some(abi) = cxx_abi_static() {
        println!("cargo:rustc-link-arg-bins={}", abi.display());
    } else {
        // Fallback for an unexpected NDK layout.
        println!("cargo:rustc-link-lib=c++_static");
    }
}

fn cxx_abi_static() -> Option<PathBuf> {
    let ndk = PathBuf::from(env::var_os("ANDROID_NDK_HOME")?);
    let target = env::var("TARGET").ok()?;
    let host = if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else if cfg!(target_os = "windows") {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    };
    let p = ndk
        .join("toolchains/llvm/prebuilt")
        .join(host)
        .join("sysroot/usr/lib")
        .join(&target)
        .join("libc++abi.a");
    p.is_file().then_some(p)
}
