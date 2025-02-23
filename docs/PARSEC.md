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


## User guide

1. Install parsec-service and parsec-tool

    * On Debian Bookworm, you will have to unfortunately use the Debian trixie (testing) repo which means it will update your libc version and other core packages like systemd!

1. Check if the service is running or not, on debian the ownership of the folder had to be adjusted but your experience may be different

    ```sh
    chown -R  parsec:parsec /var/lib/parsec/kim-mappings/sqlite/
    ```

1. Create a key

  ```sh
  parsec-tool -p 2 create-ecc-key --key-name device
  ```

2. Create a CSR

  ```sh
  parsec-tool -p 2 create-csr --key-name device > device.csr
  ```

3. Sign the CSR using your CA and store the certificate under /etc/tedge/device-certs/tedge-certificate.pem

## Appendix

### Setting up Debian Trixie repository

Create the apt list:

```sh
cat <<EOT > /etc/apt/sources.list.d/trixie.list
deb http://deb.debian.org/debian testing main contrib non-free non-free-firmware
EOT
```

Add a apt preference file to prioritize the releases (this part is not 100% tested, so please check for yourself before relying on it!):

```sh
cat <<EOT > /etc/apt/preferences.d/99-testing
Package: *
Pin: release a=bookworm
Pin-Priority: 700

Package: *
Pin: release a=testing
Pin-Priority: 650

Package: *
Pin: release a=unstable
Pin-Priority: 600
EOT
```

Install parsec

```sh
apt-get update
apt-get install --no-install-recommends -y parsec-service parsec-tool
```

### Example parsec configuration

**File: /etc/parsec/config.toml**

```toml
# Parsec Configuration File

# (Required) Core settings apply to the service as a whole rather than to individual components within it.
[core_settings]
# Whether or not to allow the service to run as the root user. If this is false, the service will refuse to
# start if it is run as root. If this is true, the safety check is disabled and the service will be allowed to
# start even if it is being run as root. The recommended (and default) setting is FALSE; allowing Parsec to
# run as root violates the principle of least privilege.
#allow_root = false
# Size of the thread pool used for processing requests. Defaults to the number of processors on
# the machine.
#thread_pool_size = 8

# Duration of sleep when the connection pool is empty. This can limit the response
# times for requests and so should be set to a low number. Default value is 10.
#idle_listener_sleep_duration = 10 # in milliseconds

# Log level to be applied across the service. Can be overwritten for certain modules which have the same
# configuration key. Possible values: "debug", "info", "warn", "error", "trace"
# WARNING: This option will not be updated if the configuration is reloaded with a different one.
log_level = "info"

# Control whether log entries contain a timestamp.
#log_timestamp = false

# Decide how large (in bytes) request bodies can be before they get rejected automatically.
# Defaults to 1MB.
#body_len_limit = 1048576

# Decide whether detailed information about errors occuring should be included in log messages.
# WARNING: the details might include sensitive information about the keys used by Parsec clients,
# such as key names or policies
#log_error_details = false

# Decide how large (in bytes) buffers inside responses from this provider can be. Requests that ask
# for buffers larger than this threshold will be rejected. Defaults to 1MB.
#buffer_size_limit = 1048576

# Decide whether deprecated algorithms and key types are allowed when generating keys or not.
# Note: While importing a deprecated key, only a warning log is generated.
# The default behaviour is to reject the deprecated primitives. Hence, the default value is false.
#allow_deprecated = false

# (Required) Configuration for the service IPC listener component.
[listener]
# (Required) Type of IPC that the service will support.
listener_type = "DomainSocket"

# (Required) Timeout of the read and write operations on the IPC channel. After the
# timeout expires, the connection is dropped.
timeout = 200 # in milliseconds

# Specify the Unix Domain Socket path. The path is fixed and should always be the default one for
# clients to connect. However, it is useful to change it for tests.
# WARNING: If a file already exists at that path, the service will remove it before creating the
# socket file.
#socket_path = "/run/parsec/parsec.sock"

# (Required) Authenticator configuration.
# WARNING: the authenticator MUST NOT be changed if there are existing keys stored in Parsec.
# In a future version, Parsec might support multiple authenticators, see parallaxsecond/parsec#271
# for details.
[authenticator]
# (Required) Type of authenticator that will be used to authenticate clients' authentication
# payloads.
# Possible values: "Direct", "UnixPeerCredentials" and "JwtSvid".
# WARNING: The "Direct" authenticator is only secure under specific requirements. Please make sure
# to read the Recommendations on a Secure Parsec Deployment at
# https://parallaxsecond.github.io/parsec-book/parsec_security/secure_deployment.html
auth_type = "UnixPeerCredentials"

# List of admins to be identified by the authenticator.
# The "name" field of each entry in the list must contain the application name (as required by the
# identifier in `auth_type`). For example, for `UnixPeerCredentials`, the names should be UIDs of
# the admin users.
# WARNING: Admins have special privileges and access to operations that are not permitted for normal
# users of the service. Only enable this feature with some list of admins if you are confident
# about the need for those permissions.
# Read more here: https://parallaxsecond.github.io/parsec-book/parsec_client/operations/index.html#core-operations
#admins = [ { name = "admin1" }, { name = "admin2" } ]

# (Required only for JwtSvid) Location of the Workload API endpoint
# WARNING: only use this authenticator if the Workload API socket is TRUSTED. A malicious entity
# owning that socket would have access to all the keys owned by clients using this authentication
# method. This path *must* be trusted for as long as Parsec is running.
#workload_endpoint="unix:///run/spire/sockets/agent.sock"

# (Required) Configuration for the components managing key info for providers.
# Defined as an array of tables: https://github.com/toml-lang/toml#user-content-array-of-tables
[[key_manager]]
# (Required) Name of the key info manager. Used to tie providers to the manager supporting them.
name = "sqlite-manager"

# (Required) Type of key info manager to be used.
# Possible values: "SQLite", "OnDisk"
# NOTE: The SQLite KIM is now the recommended type, with the OnDisk KIM to be deprecated at some
# point in the future.
manager_type = "SQLite"

# Path to the location where the database will be persisted
#store_path = "/var/lib/parsec/kim-mappings/sqlite/sqlite-key-info-manager.sqlite3"

# Example of OnDisk Key Info Manager configuration
#[[key_manager]]
# (Required) Name of the key info manager.
#name = "on-disk-manager"
# (Required) Type of key info manager to be used.
#manager_type = "OnDisk"
# Path to the location where the mappings will be persisted (in this case, the filesystem path)
#store_path = "/var/lib/parsec/mappings"

# (Required) Provider configurations.
# Defined as an array of tables: https://github.com/toml-lang/toml#user-content-array-of-tables
# IMPORTANT: The order in which providers below are declared matters: providers should be listed
# in terms of priority, the highest priority provider being declared first in this file.
# The first provider will be used as default provider by the Parsec clients. See below example
# configurations for the different providers supported by the Parsec service.

# Example of an Mbed Crypto provider configuration.
[[provider]]
# ⚠
# ⚠ WARNING: Provider name cannot change.
# ⚠ WARNING: Choose a suitable naming scheme for your providers now.
# ⚠ WARNING: Provider name defaults to "mbed-crypto-provider" if not provided, you will not be able to change
# ⚠ the provider's name from this if you decide to use the default.
# ⚠ WARNING: Changing provider name after use will lead to loss of existing keys.
# ⚠
# (Optional) The name of the provider
name = "mbed-crypto-provider"

# (Required) Type of provider.
provider_type = "MbedCrypto"

# (Required) Name of key info manager that will support this provider.
# NOTE: The key info manager only holds mappings between Parsec key name and Mbed Crypto ID, along
# with other metadata associated with the key. The keys themselves, however, are stored by the Mbed
# Crypto library by default within the working directory of the service, NOT in the same location
# as the mappings mentioned previously. If you want the keys to be persisted across reboots, ensure
# that the working directory is not temporary.
key_info_manager = "sqlite-manager"

# Example of a PKCS 11 provider configuration
[[provider]]
# ⚠
# ⚠ WARNING: Provider name cannot change.
# ⚠ WARNING: Choose a suitable naming scheme for your providers now.
# ⚠ WARNING: Provider name defaults to "pkcs11-provider" if not provided, you will not be able to change
# ⚠ the provider's name from this if you decide to use the default.
# ⚠ WARNING: Changing provider name after use will lead to loss of existing keys.
# ⚠
# (Optional) The name of the provider
name = "pkcs11-provider"
provider_type = "Pkcs11"
key_info_manager = "sqlite-manager"
# (Required for this provider) Path to the location of the dynamic library loaded by this provider.
# For the PKCS 11 provider, this library implements the PKCS 11 API on the target platform.
#library_path = "/usr/local/lib/softhsm/libsofthsm2.so"
library_path = "/usr/lib/aarch64-linux-gnu/pkcs11/opensc-pkcs11.so"
# (Optional) PKCS 11 serial number of the token that will be used by Parsec.
# If the token serial number is entered, then the slot that has the provided serial number will be used. Otherwise, if both `serial_number` and `slot_number` are given but do not match, a warning is issued and serial number takes precedence.
# Note: Matching the serial_number done after trimming the leading and trailing whitespaces for serial numbers shorter than 16 character.
#serial_number = "0123456789abcdef"
# serial_number = "DENK123456"
# (Optional) PKCS 11 slot that will be used by Parsec If Token serial number is not entered. i.e, serial_number is preferred
# If the slot number is not entered and there is only one slot available - with a valid token - it will be automatically used
#slot_number = 123456789
# (Optional) User pin for authentication with the specific slot. If not set, the sessions will not
# be logged in. It might prevent some operations to execute successfully on some tokens.
user_pin = "123456"
# (Optional) Control whether missing public key operation (such as verifying signatures or asymmetric
# encryption) are fully performed in software.
#software_public_operations = false
# (Optional) Control whether it is allowed for a key to be exportable. On some platforms creating a
# key that can be exported will fail with an obscure error. If this flag is set to false, creating
# a key with its export usage flag set to true will return a PsaErrorNotPermitted error.
#allow_export = true
```
