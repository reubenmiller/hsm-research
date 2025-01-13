package main

// source: https://github.com/salrashid123/mtls_pkcs11/blob/main/client/client.go

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/ThalesIgnite/crypto11"
	salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"

	MQTT "github.com/eclipse/paho.mqtt.golang"
)

func NewTLSConfig(clientCerts []tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: clientCerts,
	}
}

var f MQTT.MessageHandler = func(client MQTT.Client, msg MQTT.Message) {
	fmt.Printf("Received message. topic=%s, payload=%s\n", msg.Topic(), msg.Payload())
}

func GetEnv(key string, defaultValue string) string {
	v := os.Getenv(key)
	if v != "" {
		return v
	}
	return defaultValue
}

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

	pkcsModule := GetEnv("PKCS11_MODULE", "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so")
	pkcsPin := GetEnv("PKCS11_PIN", "123456")
	pkcsTokenLabel := GetEnv("PKCS11_TOKENLABEL", "rmi_macos01")

	// yubikey
	config := &crypto11.Config{
		// Note: Get token label using the following command:
		// pkcs11-tool --list-token-slots --module /opt/homebrew/lib/libykcs11.dylib
		// And copy the "token label" field

		// Option 1: using yubikey library
		// Path: "/opt/homebrew/lib/libykcs11.dylib",
		// TokenLabel: "YubiKey PIV #26756662",

		// Option 2: using opensc-pkcs11 library
		Path:       pkcsModule,
		TokenLabel: pkcsTokenLabel,

		Pin: pkcsPin,
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
	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{
	// 		ServerName:   "certauth.cryptomix.com",
	// 		Certificates: []tls.Certificate{r.TLSCertificate()},
	// 	},
	// }
	// client := &http.Client{Transport: tr}

	// resp, err := client.Get("https://certauth.cryptomix.com/json/")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

	// htmlData, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// defer resp.Body.Close()
	// fmt.Fprintf(os.Stderr, "Status: %v\n", resp.Status)
	// fmt.Printf("%s\n", htmlData)

	// MQTT client
	tlsconfig := NewTLSConfig([]tls.Certificate{r.TLSCertificate()})

	opts := MQTT.NewClientOptions()

	c8yhost := GetEnv("C8Y_DOMAIN", "thin-edge-io.eu-latest.cumulocity.com")
	if u, err := url.Parse(c8yhost); err == nil {
		c8yhost = u.Hostname()
	}

	mqttHost := fmt.Sprintf("ssl://%s:8883", c8yhost)
	fmt.Printf("Connecting to MQTT Broker: %s\n", mqttHost)
	opts.AddBroker(mqttHost)
	opts.SetClientID(GetEnv("DEVICE_ID", "rmi_macos01")).SetTLSConfig(tlsconfig)
	opts.SetDefaultPublishHandler(f)

	// Start the connection
	c := MQTT.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	c.Subscribe("s/ds", 0, nil).Wait()
	c.Publish("s/us", 0, false, "500").Wait()

	i := 0
	for range time.Tick(time.Duration(1) * time.Second) {
		if i == 1 {
			break
		}
		payload := "400,hsm,\"Event from client using hsm key (golang)\""
		c.Publish("s/us", 0, false, payload).Wait()
		fmt.Printf("Published event to Cumulocity. payload=%s\n", payload)
		i++
	}

	c.Disconnect(250)
}
