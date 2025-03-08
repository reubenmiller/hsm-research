
Note: These instructions are incomplete as discovery is still going on.

Install dependencies

```sh
apt-get install -y p11-kit tpm-tools-pkcs11 libtpm2-pkcs11-1 gnutls-bin "libtss2-*" tpm-udev tpm2-abrmd tpm2-tools tpm2-openssl
sudo usermod --append --groups tss $(whoami)
sudo usermod --append --groups tss tedge
```

View the tokens

```sh
# p11tool --list-tokens
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
	URL: pkcs11:model=SLB9672%00%00%00%00%00%00%00%00%00;manufacturer=Infineon;serial=0000000000000000;token=
	Label:
	Type: Hardware token
	Flags: RNG, Requires login, Uninitialized, uPIN uninitialized
	Manufacturer: Infineon
	Model: SLB9672
	Serial: 0000000000000000
	Module: libtpm2_pkcs11.so
```

Now if you run the same command again, you should see a new token

```sh
# p11tool --list-tokens
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
	URL: pkcs11:model=SLB9672%00%00%00%00%00%00%00%00%00;manufacturer=Infineon;serial=0000000000000000;token=device
	Label: device
	Type: Hardware token
	Flags: RNG, Requires login
	Manufacturer: Infineon
	Model: SLB9672
	Serial: 0000000000000000
	Module: libtpm2_pkcs11.so


Token 2:
	URL: pkcs11:model=SLB9672%00%00%00%00%00%00%00%00%00;manufacturer=Infineon;serial=0000000000000000;token=
	Label:
	Type: Hardware token
	Flags: RNG, Requires login, Uninitialized, uPIN uninitialized
	Manufacturer: Infineon
	Model: SLB9672
	Serial: 0000000000000000
	Module: libtpm2_pkcs11.so
```

You can set the user pin using (where the `PKCS_URI` variable should match the newly created token):

```sh
PKCS_URI='pkcs11:model=SLB9672%00%00%00%00%00%00%00%00%00;manufacturer=Infineon;serial=0000000000000000;token=tedge'
p11tool --initialize-pin "$PKCS_URI"

# GNUTLS_PIN=123456
# GNUTLS_SO_PIN=123456
# GNUTLS_NEW_SO_PIN=
```

Create a new private key

```sh
GNUTLS_PIN=123456 p11tool --login --generate-privkey ECDSA --curve=secp256r1  --label "tedge" --outfile /etc/tedge/tpm2/tedge.pub "$PKCS_URI"
```

Create a CSR using certtool

```sh
DEVICE_ID=$(tedge-identity 2>/dev/null)
cat <<EOT > cert.template
organization = "Thin Edge"
unit = "Test Device"
#state = "QLD"
#country = AU
cn = "$DEVICE_ID"
expiration_days = 365
EOT

KEY=$(p11tool --login --list-all $PKCS_URI | grep type=private | awk '{ print $2 }')
GNUTLS_PIN=123456 certtool --generate-request --template cert.template --load-privkey "$KEY" --outfile device.csr
```


## Delete all tpm tokens

```sh
rm -R $HOME/.tpm2_pkcs11/tpm2_pkcs11.sqlite3
```

## Other

### References

* cert tool - https://man7.org/linux/man-pages/man1/certtool.1.html
* p11tool - https://www.gnutls.org/manual/html_node/p11tool-Invocation.html
* tpm2-openssl - https://github.com/tpm2-software/tpm2-openssl/blob/master/docs/certificates.md

### Create private key and self-signed certificate

Note: Using the provider might not actually create a certificate which is accessible by pkcs11 later on.

```sh
openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
    -x509 -subj "/C=GB/CN=foo" -keyout testkey.pem \
    -out testcert.pem
```

## Script

```sh
#!/bin/sh
set -ex

# User must call first
# sudo usermod --append --groups tss tedge

# Set value from p11tool --list-tokens
TOKEN_URI="pkcs11:model=SLB9672%00%00%00%00%00%00%00%00%00"
export TOKEN_LABEL="tedge"
export GNUTLS_PIN=123456
export GNUTLS_SO_PIN=123456 
export TPM2_PKCS11_STORE=/etc/tedge/tpm2

mkdir -p "$TPM2_PKCS11_STORE"
p11tool --initialize "$TOKEN_URI" --label "$TOKEN_LABEL" || echo "Failed to initialize or it has already been created"

echo "Finding token's URI..."
PKCS_URI=$(p11tool --list-tokens | grep "token=$TOKEN_LABEL" | awk '{ print $2 }')
echo "Found tokens's URI: $PKCS_URI"

echo "Setting the pin and so-pin..."
p11tool --initialize-pin --initialize-so-pin --set-pin="$GNUTLS_PIN" --set-so-pin "$GNUTLS_SO_PIN" "$PKCS_URI"

echo "Generating private key..."
p11tool --login --generate-privkey ECDSA --curve=secp256r1  --label "$TOKEN_LABEL" --outfile "$TPM2_PKCS11_STORE/tedge.pub" "$PKCS_URI"

DEVICE_ID=$(tedge-identity 2>/dev/null || hostname)
echo "Creating CSR...CN=$DEVICE_ID"
cat <<EOT > "$TPM2_PKCS11_STORE/cert.template"
organization = "Thin Edge"
unit = "Test Device"
#state = "QLD"
#country = AU
cn = "$DEVICE_ID"
expiration_days = 365
EOT

CSR_PATH=$(tedge config get device.csr_path)

KEY=$(p11tool --login --list-all "$PKCS_URI" | grep type=private | awk '{ print $2 }')
GNUTLS_PIN=123456 certtool --generate-request --template "$TPM2_PKCS11_STORE/cert.template" --load-privkey "$KEY" --outfile "$CSR_PATH"
echo "Created CSR: $CSR_PATH"
cat "$CSR_PATH"

echo
echo You can list the tokens using the tedge user with the following command:
echo
echo   sudo -u tedge TPM2_PKCS11_STORE="$TPM2_PKCS11_STORE" p11tool --list-tokens
echo
echo Reset the TPM store usign
echo
echo   rm -rf "$TPM2_PKCS11_STORE"
echo
```
