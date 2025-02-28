# HSM Setup

## Step 1: Installing c8y tooling

Before you can use the HSMs you'll need to install some tooling to help you create sign Certificate Signing Requests which the HSM will generate. This can be done many ways, however for an easy integration with Cumulocity, we'll use a local CA (on your machine) by utilizing go-c8y-cli and the [c8y-tedge](https://github.com/thin-edge/c8y-tedge) extension.


1. Install [go-c8y-cli](https://goc8ycli.netlify.app/docs/installation/shell-installation/) by following the website's instructions

1. Install the c8y-tedge go-c8y-cli extension

    ```sh
    c8y extension install thin-edge/c8y-tedge
    c8y extensions update tedge
    ```

1. Activate an existing [go-c8y-cli](https://goc8ycli.netlify.app/) session to the tenant you wish to connect to

    ```sh
    set-session
    ```

    If you haven't created a go-c8y-cli session already for your Cumulocity tenant, then run the following command:

    ```sh
    c8y sessions create
    ```

    Then run `set-session` afterwards to activate the session. See the [go-c8y-cli docs](https://goc8ycli.netlify.app/docs/gettingstarted/#basics) for more details.

1. Create a new local CA certificate (this will be used to sign CSRs coming from the HSM device)

    ```sh
    c8y tedge local-ca create
    ```

    If you don't have the `c8y tedge` command, then you will need to install and update it.

    Note: Don't worry about running this command again as it won't overwrite an existing local CA certificate.

## Step 2: Generate a Private Key in your HSM

Following the HSM specific instructions to generate the required private key in the HSM of your choice.

### Yubikey

1. Install the dependencies

    **MacOS**

    ```sh
    brew install ykman yubico-piv-tool
    ```

    **Debian**

    ```sh
    apt-get install -y python3-ykman
    ```

1. Generate a private key (in the Yubikey)

    ```sh
    ykman piv keys generate --algorithm ECCP256 9a public.key
    ```

    Note: The RSA algorithms are not currently supported as the there is a signing problem when the `*PSS*` style algorithms used in the TLS 1.3 handshake (e.g. `RSA_PSS_SHA256`, `RSA_PSS_SHA384` and `RSA_PSS_SHA512`).

1. Set the desired device id of the device certificate (this will be used as the certificate's Common Name and used to identify the device)

    ```sh
    DEVICE_ID=rmi_hsm_0001
    ```

1. Create a Certificate Signing Request (CSR)

    ```sh
    ykman piv certificates request \
        --subject "CN=${DEVICE_ID},OU=Test Device,O=Thin Edge" \
        9a public.key - > device.csr
    ```

1. Sign the request to generate a device certificate (using a CA that you created in the previous steps)

    ```sh
    c8y tedge local-ca sign device.csr > device.pem
    ```

    **Note:** If you are on a device, then you can copy the device.csr from the device, sign the cert on your local machine, then copy back the certificate.

1. Save the certificate in the `.env` file (base64 encoded) as it will be used when starting the container

    ```sh
    echo "CERTPUBLIC=$(cat device.pem | base64 | tr -d '\r\n')" >> .env
    ```

Note: If you're having problems with your Yubikey, or need to recreate the private key, then reset it first using:

```sh
ykman piv reset
```

## Step 3a (MacOS): Run thin-edge.io in a container which will use the HSM's private key to verify the device certificate

Note: Before you can use this section, check the [HSM Setup](#hsm-setup) section to ensure you've configured your HSM correctly.

A start-demo.sh script has been added to help reduce the number of manual steps (this for developer usage only!).

The script does the following steps:

1. Stop any previously created p11-kit server processes, then starts a new one (in the background)
1. Detect the relevant tedge settings e.g. c8y.url, public certificate (and converts it to base64 so it can be passed to the container as an environment variable)
1. On MacOS, the p11-kit server socket will be forwarded to the colima virtual machine (if the `colima` command is found)
1. Modify the permissions of the p11-kit server socket so that it can be accessed inside the container using the default user
1. Start a container and mount the socket into it


Note: The followings steps describes the entire process from creating the initial certificates to starting a container. So if you've done some of the steps already then you can skip over some of them, but if you run into troubles, then try resetting your Yubikey and starting again.

1. Install the dependencies

    **MacOS**

    ```sh
    brew install p11-kit
    ```

1. Run the demo (`sudo` will be called to managed the p11-kit server socket permissions)

    **Note:** You will have to check the relevant PKCS#11 URI is associated to your token by running the `p11-kit list-modules` command (as the example below might not work for you):

    ```sh
    ./start-demo.sh --uri 'pkcs11:model=YubiKey%20YK5;'
    ```

    You can stop the setup by pressing `ctrl-c`. Do any changes, and re-run the script as before.

## Step 3b (Debian): Run thin-edge.io in a container which will use the HSM's private key to verify the device certificate

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

# Troubleshooting

## Check if private key exists

**On the Host**

```sh
GNUTLS_PIN=123456 p11tool --login --list-all-privkeys 'pkcs11:model=PKCS%2315%20emulated'
```

**In Container**

```sh
GNUTLS_PIN=123456 p11tool --login --list-all-privkeys 'pkcs11:model=PKCS%2315%20emulated'
```

