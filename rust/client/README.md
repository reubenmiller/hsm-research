# rust client

## Example

### Setup

Before you can run the test application, you need to run the following steps to create a device certificate, uploading it to Cumulocity and importing the keys to your Yubikey.

1. Create a client certificate using thin-edge.io

    ```sh
    tedge cert create --device-id mydevice01
    ```
    
2. Upload the certificate to Cumulocity

    ```sh
    tedge cert upload c8y
    tedge connect c8y
    ```

3. Disconnect thin-edge.io (as you'll be using the test application later)

    ```sh
    tedge disconnect c8y
    ```

4. Import the private key

    ```sh
    ykman piv keys import 9a $(tedge config get device.key_path)
    ```

5. Import the public certificate

    ```sh
    ykman piv certificates import 9a $(tedge config get device.cert_path)
    ```

6. Check that the certificate is accessible via a PKCS#11 shared library object.

    ```sh
    pkcs11-tool --list-token-slots --module /opt/homebrew/lib/libykcs11.dylib
    ```
    
    Take note of the "token label" field which will be required when running the test application

### Running the application

The following starts an MQTT client which connects to the Cumulocity MQTT Broker using

1. Configure the following environment variables

    ```sh
    export DEVICE_ID="<device_id/cert_common_name>"
    export C8Y_DOMAIN=thin-edge-io.eu-latest.cumulocity.com
    export PKCS11_MODULE=/opt/homebrew/lib/libykcs11.dylib
    export PKCS11_PIN="123456"
    ```

2. Run the test application

    ```sh
    cargo run
    ```

    *Output*

    ```sh
    Public Key: "1.2.840.10045.2.1"
    Subject: "CN=rmi_macos01, O=Thin Edge, OU=Test Device"
    Issuer: "CN=rmi_macos01, O=Thin Edge, OU=Test Device"
    Serial: "abcdefh37d74a02d59dc4a7682dcd0728ed13eea"
    Matching scheme: Some("ECDSA_NISTP256_SHA256")
    Using scheme: Some("ECDSA_NISTP256_SHA256")

    Private Key Id: "\u{1}"
    Private Key Class: "CKO_PRIVATE_KEY"
    Private Key Label: "PIV AUTH key"
    Signed data: "0��4㮵lu\u{14}�|Y���\u{17}�\"���r\rl�%M�\u{7f}����c�9�Q��\u{3}*.{�\u{b}X�I���B\u{31c}�����\u{4}�"
    Error = Io(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })
    ```
