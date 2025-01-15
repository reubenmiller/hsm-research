## Debian   

### Setup

1. Install dependencies

    ```sh
    apt-get update
    apt-get install -y openssl libengine-pkcs11-openssl gnutls-bin opensc
    ```

    Optional dependency if you need to create certificates or import them to your yubikey. See the [Yubikey section for details](#importing-private-and-public-keys)

    ```sh
    apt-get install -y yubikey-manager
    ```

1. Add the following options to the /etc/mosquitto/mosquitto.conf file (before the `include_dir` lines)

    ```sh
    tls_engine pkcs11
    tls_keyform engine
    ```

1. Replace the `bridge_keyfile` value in `/etc/tedge/mosquitto-conf/c8y-bridge.conf` with the PKCS#11 URL for the related private certificate

    ```sh
    bridge_keyfile pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=b98efbc09b13980d;token=rpi5-d83addab8e9f;id=%01;object=PIV%20AUTH%20key;type=private;pin-value=123456
    ```

1. Restart mosquitto

    ```sh
    systemctl restart mosquitto
    ```


### Importing private and public keys

#### Yubikey

##### Import existing private key

```sh
ykman piv keys import 9a $(tedge config get device.key_path)
```

##### Import existing public key

```sh
ykman piv certificates import 9a $(tedge config get device.cert_path)
```

##### Get Private Key URL (required to access it)

```sh
p11tool --login --list-privkeys 2>/dev/null | grep --fixed-strings "$(tedge config get device.id)"
```

*Example Output*

```sh
pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=b98efbc09b13980d;token=rpi5-d83addab8e9f
```

Or you might have some luck with the following one-liner to get the URL that need to match to the private keys (assuming the label includes the certificate's common name used by thin-edge.io):

```sh
p11tool --login --list-privkeys 2>/dev/null "$(p11tool --login --list-privkeys 2>/dev/null | grep --fixed-strings "$(tedge config get device.id)")" | grep "URL:" | awk -F ' ' '{print $2 ";pin-value=123456"}'
```

*Example Output*

```sh
pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=b98efbc09b13980d;token=rpi5-d83addab8e9f;id=%01;object=PIV%20AUTH%20key;type=private
```
