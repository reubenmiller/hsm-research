# Accessing HSM from containers

The PKCS#11 interface, which can be used to access HSMs, can be exposed to containers by creating a pk11-kit server which provides a unix socket which can then be mounted into the container which needs to access it.

## Limitations

* Requires a service to be installed on the host (e.g. `p11-kit-server.service` and `p11-kit-server.socket`)

* The container's gid (group id) needs to match host's gid assigned to the unix socket being mounted into the container so that the user can access the socket

**References**

* https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html

## Installing pk11-kit server on a host

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
    ExecStart=/usr/bin/p11-kit server -f -u tedge -g tedge -n %t/p11-kit/pkcs11 pkcs11:model=PKCS%%2315%%20emulated;manufacturer=piv_II;serial=b98efbc09b13980d;token=rpi5-d83addab8e9f
    Restart=on-failure

    [Install]
    Also=p11-kit-server.socket
    WantedBy=default.target
    ```

1. Configure the opensc-pkcs11 module

    ```sh
    echo "module: /usr/lib/aarch64-linux-gnu/pkcs11/opensc-pkcs11.so" > /usr/share/p11-kit/modules/opensc-pkcs11.module
    ```

1. Reload the systemd

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

## Container examples

### Debian (with non-root user)

1. Start the container

    ```sh
    docker run -it --rm -v /run/p11-kit/pkcs11:/run/p11-kit/pkcs11 -e P11_KIT_SERVER_ADDRESS=unix:path=/run/p11-kit/pkcs11 debian:12
    ```

2. Create a group with the same gid of the host

    **Note:** a gid of `992` is used in this example, you will have to check the gid of the unix socket yourself

    ```sh
    groupadd --system tedge -g992
    useradd --system --no-create-home --shell /sbin/nologin --gid tedge tedge
    ```

3. Install the dependencies in the container

    ```sh
    apt-get update
    apt-get install -y sudo openssl libengine-pkcs11-openssl gnutls-bin opensc
    mkdir -p /etc/pkcs11/modules
    echo "module: /usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-client.so" > /etc/pkcs11/modules/p11-kit-client.module

    # Test connection with
    sudo -E -u tedge p11tool --provider p11-kit-client.so --list-tokens
    ```

### Alpine linux (with root user)

1. Start the container

    ```sh
    docker run -it --rm -v /run/p11-kit/pkcs11:/run/p11-kit/pkcs11 -e P11_KIT_SERVER_ADDRESS=unix:path=/run/p11-kit/pkcs11 alpine:3.18
    ```

2. Install the dependencies in the container

    ```sh
    apk add sudo openssl p11-kit-server gnutls gnutls-utils opensc
    mkdir -p /etc/pkcs11/modules
    echo "module: /usr/lib/pkcs11/p11-kit-client.so" > /etc/pkcs11/modules/p11-kit-client.module

    p11tool --provider p11-kit-client.so --list-tokens
    ```

**Example Output**

```sh
# p11tool --provider p11-kit-client.so --list-tokens
Token 0:
	URL: pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=b98efbc09b13980d;token=rpi5-d83addab8e9f
	Label: rpi5-d83addab8e9f
	Type: Hardware token
	Flags: RNG, Requires login
	Manufacturer: piv_II
	Model: PKCS#15 emulated
	Serial: b98efbc09b13980d
	Module:
```

### Alpine linux (non-root) - TODO

TODO

* Experiment changing tedge group id on initialization using `groupmod -g 992 tedge`, where the target gid id.
