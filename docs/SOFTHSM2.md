## SoftHSM2

**Warning** These instructions don't yet work but it should be a good starting point.

### Installation

```sh
# macos
brew install softhsm
```

### Key Setup

**List**

```
softhsm2-util --show-slots
```

### Import

1. Initialize the slot (if not already initialized)

    ```sh
    softhsm2-util --init-token --slot 0 --label "device-cert"
    ```

2. Import the private key

    ```sh
    PUB_PRIV_KEY=$(
        cat "$(tedge config get device.key_path)" && cat "$(tedge config get device.cert_path)"
    )
    softhsm2-util \
        --import <(echo "$PUB_PRIV_KEY") \
        --token "device-cert" \
        --label device-cert \
        --id 01 \
        --pin 123456 \
        --force
    ```

    Or only import the private key (skipping the public key)

    ```sh
    softhsm2-util \
        --import $(tedge config get device.key_path) \
        --no-public-key \
        --token "device-cert" \
        --label device-cert \
        --id 01 \
        --pin 123456
    ```

3. Find the SoftHSM2 file and add it to the modules

    ```sh
    find /opt/homebrew -name "*libsofthsm2*"
    ```

    The
    ```sh
    echo "module: /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so" > /opt/homebrew/etc/pkcs11/modules/softhsm2.module
    ```

4. Start the test client

    ```sh
    ```

3. Import the public key

    ```
    softhsm2-util --import $(tedge config get device.key_path) --token "device-cert" --label device-cert --id 01
    ```
