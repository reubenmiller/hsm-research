# Parsec

Updated: 2025-02-07

## Overview

Whilst the idea behind parsec is great, the integrating it seems to be difficult.

**Advantages**

* Good selection of HSM providers out of the box (though haven't been verified due to lack of access to hardware)
* Yocto support (see [meta-security](https://git.yoctoproject.org/meta-security/tree/meta-parsec) but building hasn't been tested yet)
* Public package ([parsec-service](https://packages.debian.org/trixie/parsec-service)) is available in future debian versions (e.g. Trixie)

**Disadvantages**

* Public package is relatively new and not supported on the current main OS versions (e.g. Debian bookworm or earlier)
* Hard to build / cross-compile
* pkcs11-provider does not support Yubikey
* Hard to debug (lack of verbose error messages)

## Problems

Below shows some of the details behind some of the problems found during discovery.

### Error messages in the pkcs11-provider are not very descriptive

Debugging provider issues is very difficult due to very limited output from the parsec server or parsec-tool.

For example trying to generate a private key using the `parsec-tool` returns a generic error, and the `parsec` log output just shows an error which is referring to documentation that no longer exists (there is no Section 4.1 under the [documentation](https://parallaxsecond.github.io/parsec-book/)).

```log
[INFO  parsec_service::front::front_end] New request received from application name "parsec-tool"
[TRACE parsec_service::back::dispatcher] dispatch_request ingress
[TRACE parsec_service::back::backend_handler] execute_request ingress
[TRACE parsec_service::providers::pkcs11] psa_generate_key ingress
[ERROR parsec_service::providers::pkcs11::key_management] Generate key status; Error: PKCS11 error: An invalid value was specified for a particular attribute in a template.  See Section 4.1 for more information.
[ERROR parsec_service::providers::pkcs11::utils] Error converted to PsaErrorCommunicationFailure; Error: An invalid value was specified for a particular attribute in a template.  See Section 4.1 for more information.
[TRACE parsec_service::back::dispatcher] execute_request egress
[TRACE parsec_service::front::front_end] dispatch_request egress
[INFO  parsec_service::front::front_end] Response for application name "parsec-tool" sent back
```

### Incompatible with Yubikeys via the PKCS#11 interface

The pkcs11-provider of parsec does not detect existing keys from a Yubikey.

And it seems that all interactions with the yubikey do not function for reasons unknown.

### Cross compiling is difficult

Cross compiling parsec is difficult as there are many c libraries

For example:

```sh
build_with_zig_fallback() {
    arch="$1"
    echo "Building target: $arch"
    rm -rf "target/$arch"
    cargo build --release --features "direct-authenticator,unix-peer-credentials-authenticator,pkcs11-provider,mbed-crypto-provider,tpm-provider" --target "$arch" ||
    cargo-zigbuild build --release --features "direct-authenticator,unix-peer-credentials-authenticator,pkcs11-provider,mbed-crypto-provider" --target "$arch"
}
```


#### tpm-provider is not cross compilable

Due to the dependency to `tss-esapi-sys`, cross-compiling very difficult / .

Below is the error when trying to compile on a x86_64 host for the `aarch64-unknown-linux-gnu` target.

```sh
error: failed to run custom build command for `tss-esapi-sys v0.5.0`

Caused by:
  process didn't exit successfully: `/app/parsec/target/release/build/tss-esapi-sys-19d4332e7084668d/build-script-build` (exit status: 101)
  --- stdout
  cargo:rerun-if-env-changed=TSS2_SYS_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_ALLOW_CROSS_aarch64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_ALLOW_CROSS_aarch64_unknown_linux_gnu
  cargo:rerun-if-env-changed=TARGET_PKG_CONFIG_ALLOW_CROSS
  cargo:rerun-if-env-changed=PKG_CONFIG_ALLOW_CROSS
  cargo:rerun-if-env-changed=PKG_CONFIG_aarch64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_aarch64_unknown_linux_gnu
  cargo:rerun-if-env-changed=TARGET_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_aarch64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_aarch64_unknown_linux_gnu
  cargo:rerun-if-env-changed=TARGET_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR

  --- stderr
  thread 'main' panicked at /opt/rust/registry/src/index.crates.io-6f17d22bba15001f/tss-esapi-sys-0.5.0/build.rs:42:14:
  Failed to find tss2-sys library.: pkg-config has not been configured to support cross-compilation.
```
