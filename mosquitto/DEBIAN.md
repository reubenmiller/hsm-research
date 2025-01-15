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

## Accessing host HSM from a Container

This section is only partially complete and is has the following limitations:

* container can only access the unix socket using a root user

References:
* https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html

1. Create the following systemd files

    **file: /etc/systemd/system/p11-kit-server.socket**

    ```ini
    [Unit]
    Description=p11-kit server

    [Socket]
    Priority=6
    Backlog=5
    ListenStream=%t/p11-kit/pkcs11
    SocketMode=0600

    [Install]
    WantedBy=sockets.target
    ```

    **file: /etc/systemd/system/p11-kit-server.service**

    ```ini
    [Unit]
    Description=p11-kit server
    Documentation=man:p11-kit(8)

    Requires=p11-kit-server.socket

    [Service]
    Type=simple
    StandardError=journal
    #ExecStart=/usr/bin/p11-kit server -f -n %t/p11-kit/pkcs11 pkcs11:
    ExecStart=/usr/bin/p11-kit server -f -n %t/p11-kit/pkcs11 pkcs11:model=PKCS%%2315%%20emulated;manufacturer=piv_II;serial=b98efbc09b13980d;token=rpi5-d83addab8e9f
    Restart=on-failure

    [Install]
    Also=p11-kit-server.socket
    WantedBy=default.target
    ```

1. Configure the opensc-pkcs11 module

    ```sh
    echo "module: /usr/lib/aarch64-linux-gnu/pkcs11/opensc-pkcs11.so" > /usr/share/p11-kit/modules/opensc-pkcs11.module
    ```

1. Reload

    ```sh
    systemctl daemon-reload
    systemctl enable p11-kit-server.service
    systemctl start p11-kit-server.service
    ```

1. Check if the pk11 server is reachable (from the host)

    ```sh
    export P11_KIT_SERVER_ADDRESS=unix:path=/run/p11-kit/pkcs11
    ```

    Check if there are now more tokens accessible

    ```sh
    echo "module: /usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-client.so" > /etc/pkcs11/modules/p11-kit-client.module

    p11tool --list-tokens
    ```

1. Start a docker container and install dependencies

    ```sh
    docker run -it --rm -v /run/p11-kit/pkcs11:/run/p11-kit/pkcs11 -e P11_KIT_SERVER_ADDRESS=unix:path=/run/p11-kit/pkcs11 debian:12
    ```

    ```sh
    apt-get update
    apt-get install -y openssl libengine-pkcs11-openssl gnutls-bin opensc
    mkdir -p /etc/pkcs11/modules
    echo "module: /usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-client.so" > /etc/pkcs11/modules/p11-kit-client.module

    # Test connection with
    p11tool --provider p11-kit-client.so --list-tokens
    ```
