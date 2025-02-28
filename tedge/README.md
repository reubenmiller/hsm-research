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
    echo "CERTPUBLIC=$(cat device.pem | base64)" >> .env
    ```

Note: If you're having problems with your Yubikey, or need to recreate the private key, then reset it first using:

```sh
ykman piv reset
```

## Step 3: Run thin-edge.io in a container which will use the HSM's private key to verify the device certificate

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
