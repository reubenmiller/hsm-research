## Pre-requisites

### MacOS

1. Install the following packages using homebrew

    ```sh
    brew install p11-kit ykman yubico-piv-tool
    ```

1. Install the tedge via the [homebrew formula](https://github.com/thin-edge/homebrew-tedge) and follow the on-screen instructions

    ```sh
    brew tap thin-edge/tedge
    brew install tedge
    ```

    Note: The tedge homebrew formula will automatically install mosquitto and also prompt you on how to set all the dependencies up (e.g. load the custom TEDGE_CONFIG_DIR variable) so you don't have to do all of this yourself.

1. Add a module to the pkcs11 which points p11-kit to the shared object library for Yubikey

    ```sh
    mkdir -p "$(brew --prefix)/etc/pkcs11/modules"
    cat <<EOT > "$(brew --prefix)/etc/pkcs11/modules/yk-pkcs11.module"
    module: $(brew --prefix)/lib/libykcs11.dylib
    priority: 1
    EOT
    ```

    You should be able to check which modules are detected by using the following command:

    ```sh
    p11-kit list-modules
    ```

### Check 1: Access Yubikey directly from Host (via cryptoki API)

To run it natively, you will need to install rust toolchain via [rustup](https://rustup.rs/) as you will need to build the package from source.

1. Compile the tedge binary

    ```sh
    cargo install tedge --git https://github.com/thin-edge/thin-edge.io.git --rev refs/pull/3366/head
    ```

1. Override tedge homebrew binary with the manually built binary

    ```sh
    brew unlink tedge
    cp "$HOME/.cargo/bin/tedge" "$(brew --prefix)/bin/tedge"
    ```

1. Configure thin-edge.io to use certificates

    ```sh
    # Optional: If a custom tedge configuration dir is being used
    export TEDGE_CONFIG_DIR=/opt/homebrew/etc/tedge

    tedge config set c8y.url "$C8Y_DOMAIN"
    tedge config set device.cryptoki.enable true
    tedge config set device.cryptoki.pin 123456
    tedge config set mqtt.bridge.built_in true
    tedge config set device.cryptoki.module_path "$(brew --prefix)/lib/libykcs11.dylib"
    ```

1. Create a key pair using tedge (to allow for local debugging)

    ```sh
    tedge cert create --device-id mydevice0001
    tedge cert upload c8y
    ```

1. Import the public and private key into your Yubikey 5 device

    ```sh
    ykman piv keys import 9a "$(tedge config get device.key_path)"
    ykman piv certificates import 9a "$(tedge config get device.cert_path)"
    ```

1. Move the private key (keep the private key for debugging purposes)

    ```sh
    mv "$(tedge config get device.key_path)" "$(tedge config get device.key_path).bak"
    ```

    Moving the private key ensure that thin-edge.io won't be reading from it, and only using the private key inside the Yubikey

1. Bootstrap the device (by registering it manually in the cloud)

    ```sh
    tedge connect c8y
    tedge disconnect c8y
    ```


### Check 2: Access Yubikey via the p11-kit server

1. Configure thin-edge.io to use the p11-kit client module

    ```sh
    tedge config set device.cryptoki.module_path "$(brew --prefix)/lib/pkcs11/p11-kit-client.so"
    ```

    Note: It is recommended to check if the path exists, and if you can't find the `p11-kit-client.so`, then you could try searching for it using:

    ```sh
    find "$(brew --prefix)" -name "p11-kit-client.so"
    ```

1. Start the p11-kit server (which creates a unix socket which the p11-kit client will use)

    ```sh
    p11-kit server -f -n /tmp/pkcs11 "pkcs11:model=PKCS%2315%20emulated"
    ```

    Note: The last positional argument is the PKCS#11 uri which refers to your token on your machine which should match one of the token URI's from the `p11-kit list-modules` output.

1. Configure tedge to use the p11-kit-client cryptoki library (the exact settings is printed on the console from the previous step)

    ```sh
    P11_KIT_SERVER_ADDRESS=unix:path=/tmp/pkcs11; export P11_KIT_SERVER_ADDRESS;
    ```

1. Start the mapper manually (as starting the service won't work as the `P11_KIT_SERVER_ADDRESS` environment variable won't be set for the `tedge-mapper` service as it is launched an independent process)

    ```sh
    tedge run tedge-mapper c8y
    ```


## Running from a Container

1. Firstly, you will need to find the PKCS#11 URI which corresponds to your token

    List the modules (assuming you've already configured Yubikey's PKCS#11 module)

    ```sh
    p11-kit list-modules
    ```

    You don't need the full URI (but you can use it if you want).

1. Start a p11-kit server (you can reuse the previously started p11-kit server if it is already running)

    ```sh
    p11-kit server -f -n /tmp/pkcs11 "pkcs11:model=PKCS%2315%20emulated"
    ```

    Note: The last positional argument is the PKCS#11 uri which refers to your token on your machine which should match one of the token URI's from the `p11-kit list-modules` output.

1. Forward the socket to colima's virtual machine (the docker host)

    ```sh
    colima ssh -- sudo rm -rf /tmp/pkcs11
    ssh \
        -i "/Users/$(whoami)/.colima/_lima/_config/user" \
        -R /tmp/pkcs11:/tmp/pkcs11 \
        127.0.0.1 -p $(colima ssh-config | grep Port | awk '{print $2}')
    ```

    Note: This step is required as on MacOS as docker runs inside a Virtual Machine and docker volume mounts are relative to the docker container host which is the Virtual Machine and not MacOS. But using SSH we can forward the unix socket from MacOS to the Virtual Machine.

1. Create a .env file (next to the docker-compose.yaml file)

    ```sh
    cat <<EOT >> .env
    C8Y_DOMAIN=$C8Y_DOMAIN
    USERID=501
    GROUPID=1000
    CERTPUBLIC=$(cat "$(tedge config get device.cert_path)" | base64)
    EOT
    ```

    Edit the values to match the user and group ownership of the p11-kit unix socket. For example, if you're using MacOS and colima, you can check

    ```sh
    colima ssh -- ls -n /tmp/pkcs11
    ```

    ```sh
    srw------- 1 501 1000 0 Feb 10 20:41 /tmp/pkcs11
    ```

    The first number `501` is the user id and the second number, `1000` is the group id. These values may be different on your machine.

1. Start the container

    ```sh
    docker compose up --build
    ```

1. Open up a shell inside the container

    ```sh
    docker compose exec bash

    tedge mqtt sub '#'
    ```


## Troubleshooting

### Colima socket forwarding isn't working

Try deleting the socket in the colima vm, or even change the name of the file.

```sh
colima ssh -- sudo rm -rf /tmp/pkcs11
```

## HSM Setup

**pre-requisites**

1. Install [go-c8y-cli](https://goc8ycli.netlify.app/docs/installation/shell-installation/) by following the websites instructions

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


### Yubikey

1. Install the dependencies

    **MacOS**

    ```sh
    brew install ykman yubico-piv-tool
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

1. Save the certificate in the `.env` file (base64 encoded) as it will be used when starting the container

    ```sh
    echo "CERTPUBLIC=$(cat device.pem | base64)" >> .env
    ```

Note: If you're having problems with your Yubikey, or need to recreate the private key, then reset it first using:

```sh
ykman piv reset
```

## Start demo using a script

Note: Before you can use this section, check the [HSM Setup](#hsm-setup) section to ensure you've configured your HSM correctly.

A start-demo.sh script has been added to help reduce the number of manual steps (this for developer usage only!).

The script does the following steps:

1. Stop any previously created p11-kit server processes, then starts a new one (in the background)
1. Detect the relevant tedge settings e.g. c8y.url, public certificate (and converts it to base64 so it can be passed to the container as an environment variable)
1. On MacOS, the p11-kit server socket will be forwarded to the colima virtual machine (if the `colima` command is found)
1. Modify the permissions of the p11-kit server socket so that it can be accessed inside the container using the default user
1. Start a container and mount the socket into it


Note, the followings steps describes the entire process from creating the initial certificates to starting a container. So if you've done some of the steps already then you can skip over some of them, but if you run into troubles, then try resetting your Yubikey and starting again.

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
