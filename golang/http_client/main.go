package main

// source: https://github.com/salrashid123/mtls_pkcs11/blob/main/client/client.go

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/ThalesIgnite/crypto11"
	salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"
)

func main() {
	// var slotNum *int
	// slotNum = new(int)
	// *slotNum = 0

	// softhsm
	// export SOFTHSM2_CONF=/home/srashid/Desktop/misc/soft_hsm/softhsm.conf
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	// 	TokenLabel: "token1",
	// 	Pin:        "mynewpin",
	// }

	// yubikey
	config := &crypto11.Config{
		// Note: Get token label using the following command:
		// pkcs11-tool --list-token-slots --module /opt/homebrew/lib/libykcs11.dylib
		// And copy the "token label" field

		// Option 1: using yubikey library
		// Path: "/opt/homebrew/lib/libykcs11.dylib",
		// TokenLabel: "YubiKey PIV #26756662",

		// Option 2: using opensc-pkcs11 library
		Path:       "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
		TokenLabel: "rmi_macos01",

		Pin: "123456",
	}

	// tpm
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1",
	// 	TokenLabel: "token1",
	// 	Pin:        "mynewpin",
	// }

	ctx, err := crypto11.Configure(config)
	if err != nil {
		log.Fatal(err)
	}

	defer ctx.Close()

	// clientCaCert, err := os.ReadFile("ca_scratchpad/ca/root-ca.crt")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// clientCaCertPool := x509.NewCertPool()
	// clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	r, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
		Context: ctx,
		// PkcsId:         nil,                                      //softhsm
		// PkcsLabel:      []byte("keylabel2"),                      //softhsm
		// PublicCertFile: "ca_scratchpad/certs/softhsm-client.crt", //softhsm

		PkcsId: []byte{1}, //yubikey
		// PkcsLabel: []byte("X.509 Certificate for PIV Authentication"), //yubikey
		// PublicCertFile: "certs/yubikey-client.crt", //yubikey or omit if PKCS device has cert already

		// PkcsId:         nil,                  //tpm
		// PkcsId: []byte{0}, //tpm
		// // PkcsLabel:      []byte("keylabel1"),  //tpm https://github.com/ThalesIgnite/crypto11/issues/82
		// PublicCertFile: "certs/tpm-client.crt", //tpm
	})
	if err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// RootCAs:      clientCaCertPool,
			ServerName:   "certauth.cryptomix.com",
			Certificates: []tls.Certificate{r.TLSCertificate()},
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://certauth.cryptomix.com/json/")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Fprintf(os.Stderr, "Status: %v\n", resp.Status)
	fmt.Printf("%s\n", htmlData)
}
