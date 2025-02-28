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
    ExecStart=/usr/bin/p11-kit server -f -u tedge -g tedge -n %t/p11-kit/pkcs11 pkcs11:model=PKCS%%2315%%20emulated;manufacturer=piv_II;
    # Or use a more exact filter
    #ExecStart=/usr/bin/p11-kit server -f -u tedge -g tedge -n %t/p11-kit/pkcs11 pkcs11:model=PKCS%%2315%%20emulated;manufacturer=piv_II;serial=b98efbc09b13980d;token=rpi5-d83addab8e9f
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

### Using the community example package: tedge-p11-kit-server

1. Install a pre-configured p11-kit server package

    ```sh
    apt-get install tedge-p11-kit-server gnutls-bin
    ```

1. List the tokens and their URI's, and note down the URI which is associated for the token that you wish to use

    ```sh
    p11tool --list-tokens
    ```

    *Example output*

    ```sh
    Token 0:
        URL: pkcs11:model=p11-kit-trust;manufacturer=PKCS%2311%20Kit;serial=1;token=System%20Trust
        Label: System Trust
        Type: Trust module
        Flags: uPIN uninitialized
        Manufacturer: PKCS#11 Kit
        Model: p11-kit-trust
        Serial: 1
        Module: p11-kit-trust.so


    Token 1:
        URL: pkcs11:model=PKCS%2315%20emulated;manufacturer=www.CardContact.de;serial=DENK0400089;token=SmartCard-HSM%20%28UserPIN%29
        Label: SmartCard-HSM (UserPIN)
        Type: Hardware token
        Flags: RNG, Requires login
        Manufacturer: www.CardContact.de
        Model: PKCS#15 emulated
        Serial: DENK0400089
        Module: /usr/lib/aarch64-linux-gnu/pkcs11/opensc-pkcs11.so


    Token 2:
        URL: pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=00000000;token=PIV_II
        Label: PIV_II
        Type: Hardware token
        Flags: RNG, Requires login
        Manufacturer: piv_II
        Model: PKCS#15 emulated
        Serial: 00000000
        Module: /usr/lib/aarch64-linux-gnu/pkcs11/opensc-pkcs11.so
    ```

1. Edit the configuration and add your desired PKCS11 token URI

    ```sh
    /etc/tedge-p11-kit-server/config.env
    ```

    *Example contents*

    ```sh
    TARGET_PKCS11_URI=pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II
    ```

1. Restart the tedge p11 kit service

    ```sh
    systemctl restart tedge-p11-kit-server.service
    ```

    You can check the status of the server and if the environment variables (read from the `config.env`) are interpreted correctly.

    ```sh
    # systemctl status tedge-p11-kit-server
    ● tedge-p11-kit-server.service - tedge-p11-kit server
        Loaded: loaded (/usr/lib/systemd/system/tedge-p11-kit-server.service; enabled; preset: enabled)
        Active: active (running) since Fri 2025-02-28 11:53:59 GMT; 3min 22s ago
    Invocation: 942e34b07f80469686c588cf96d10943
    TriggeredBy: ● tedge-p11-kit-server.socket
        Docs: man:p11-kit(8)
    Main PID: 2461409 (p11-kit-server)
        Tasks: 1 (limit: 4464)
        Memory: 496K (peak: 4.5M)
            CPU: 70ms
        CGroup: /system.slice/tedge-p11-kit-server.service
                └─2461409 server -f -u tedge -g tedge -n /run/tedge-p11-kit-server/pkcs11 "pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II"

    Feb 28 11:53:59 rpi5-d83addab8e9f systemd[1]: Started tedge-p11-kit-server.service - tedge-p11-kit server.
    Feb 28 11:53:59 rpi5-d83addab8e9f p11-kit[2461409]: P11_KIT_SERVER_ADDRESS=unix:path=/run/tedge-p11-kit-server/pkcs11; export P11_KIT_SERVER_ADDRESS;
    Feb 28 11:53:59 rpi5-d83addab8e9f p11-kit[2461409]: P11_KIT_SERVER_PID=2461409; export P11_KIT_SERVER_PID;
    ```

1. Verify if the unix socket is accessible from the host

    ```sh
    CLIENT_SO_FILE=$(find /usr/lib -name p11-kit-client.so | head -n1)
    sudo -u tedge sh -c "export P11_KIT_SERVER_ADDRESS=unix:path=/run/tedge-p11-kit-server/pkcs11; export P11_KIT_SERVER_PID=2449252; pkcs11-tool --module '$CLIENT_SO_FILE' --list-token-slots"
    ```

    *Example output*

    ```sh
    Available slots:
    Slot 0 (0x11): Yubico YubiKey OTP+FIDO+CCID 01 00
    token label        : PIV_II
    token manufacturer : piv_II
    token model        : PKCS#15 emulated
    token flags        : login required, rng, token initialized, PIN initialized
    hardware version   : 0.0
    firmware version   : 0.0
    serial num         : 00000000
    pin min/max        : 4/8
    ```

1. Download the docker compose file

    ```sh
    wget https://raw.githubusercontent.com/reubenmiller/hsm-research/refs/heads/main/tedge/docker-compose.yaml
    ```

1. Configure the `.env` file with the settings that will be used by the docker compose file

    **file: .env**

    ```sh
    CERTPUBLIC=<public_cert_pem_contents_base64_encoded>
    SOCKET_PATH=/run/tedge-p11-kit-server/pkcs11
    C8Y_DOMAIN=thin-edge-io.eu-latest.cumulocity.com
    TEDGE_DEVICE_CRYPTOKI_PIN=123456
    ```

1. Start the container

    ```sh
    docker compose up
    ```

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


## MacOS

Running on MacOS has the additional complication that docker is running from within a virtual machine, so the p11-kit server (which runs on the host) needs to expose its unix socket to the virtual machine running the container engine (so the container can bind-mount the socket within the container).

These instructions assume you already have `colima` installed on your Mac.

1. In a new console, start the p11-kit server

    ```sh
    p11-kit server -f -n /tmp/pkcs11 "pkcs11:model=PKCS%2315%20emulated"
    ```

    If you're unsure on the url to use, try using `p11-kit` to list the modules and find the token related to your Yubikey:

    ```sh
    p11-kit list-modules
    ```

2. In a new console, use ssh to forward the p11-kit socket to the colima's virtual machine

    Though you'll need to know colima's ssh port first, and the ssh key used by default:

    ```sh
    colima ssh-config
    ```

    Then add the ssh key to your ssh agent, then run the ssh command to forward the socket.

    ```sh
    ssh-add /Users/reubenmiller/.colima/_lima/_config/user
    ssh \
    -R /tmp/pkcs11:/tmp/pkcs11 \
    127.0.0.1 -p 49267
    ```

3. Start the docker container

    ```sh
    cd rust/client
    echo "C8Y_DOMAIN=example.c8y.io" >> .env
    just run-container-alpine
    ```
