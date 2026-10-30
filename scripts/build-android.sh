#!/usr/bin/env bash
# Build libmeow for Android.
#
# cargo-ndk supplies CC/AR/linker for Rust; BoringSSL is built by boring-sys
# through the `cmake` crate, which needs a per-target toolchain file that
# sets ANDROID_ABI (cargo-ndk does not provide one). Mirrors meow-android's
# Gradle cargo setup.
set -euo pipefail

ABI="${1:-arm64-v8a}"
PROFILE="${2:-release}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/30.0.16248370}"
SDK_CMAKE="${SDK_CMAKE:-$HOME/Android/Sdk/cmake/3.22.1/bin/cmake}"
MIN_SDK="${MIN_SDK:-26}"

case "$ABI" in
  arm64-v8a) TRIPLE=aarch64-linux-android; CMAKE_ABI=arm64-v8a ;;
  armeabi-v7a) TRIPLE=armv7-linux-androideabi; CMAKE_ABI=armeabi-v7a ;;
  x86) TRIPLE=i686-linux-android; CMAKE_ABI=x86 ;;
  x86_64) TRIPLE=x86_64-linux-android; CMAKE_ABI=x86_64 ;;
  *) echo "unsupported ABI: $ABI" >&2; exit 2 ;;
esac

TOOLCHAIN_DIR="$ROOT/build/cmake-toolchains"
mkdir -p "$TOOLCHAIN_DIR" "$ROOT/build/jniLibs"
WRAPPER="$TOOLCHAIN_DIR/$TRIPLE.cmake"
cat >"$WRAPPER" <<EOF
set(ANDROID_ABI $CMAKE_ABI)
set(ANDROID_PLATFORM android-$MIN_SDK)
include("$NDK/build/cmake/android.toolchain.cmake")
EOF

export ANDROID_NDK_HOME="$NDK"
export BORING_BSSL_RUST_CPPLIB=c++_static
[ -x "$SDK_CMAKE" ] && export CMAKE="$SDK_CMAKE"
# cargo-ndk does not read rust-android-gradle's link-arg variable; force
# 16 KB ELF segment alignment through rustc instead.
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384"

# Target-specific toolchain file: env(1) because CMake expects a variable
# name with hyphens, which bash cannot export.
TOOLCHAIN_ENV="CMAKE_TOOLCHAIN_FILE_$TRIPLE=$WRAPPER"
SYSROOT="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
CLANG_ARGS="--target=$TRIPLE$MIN_SDK --sysroot=$SYSROOT -I$SYSROOT/usr/include -I$SYSROOT/usr/include/$TRIPLE -D__ANDROID_API__=$MIN_SDK"
BINDGEN_ENV="BINDGEN_EXTRA_CLANG_ARGS=$CLANG_ARGS"
BINDGEN_ENV_TARGET="BINDGEN_EXTRA_CLANG_ARGS_$TRIPLE=$CLANG_ARGS"
BINDGEN_ENV_UNDERSCORE="BINDGEN_EXTRA_CLANG_ARGS_${TRIPLE//-/_}=$CLANG_ARGS"

cd "$ROOT"
if [ "$PROFILE" = "debug" ]; then
  env "$TOOLCHAIN_ENV" "$BINDGEN_ENV" "$BINDGEN_ENV_TARGET" "$BINDGEN_ENV_UNDERSCORE" \
    cargo ndk -t "$ABI" -P "$MIN_SDK" -o "$ROOT/build/jniLibs" build -p meow-android
else
  env "$TOOLCHAIN_ENV" "$BINDGEN_ENV" "$BINDGEN_ENV_TARGET" "$BINDGEN_ENV_UNDERSCORE" \
    cargo ndk -t "$ABI" -P "$MIN_SDK" -o "$ROOT/build/jniLibs" build --release -p meow-android
fi
ls -lh "$ROOT/build/jniLibs/$ABI/libmeow.so"
