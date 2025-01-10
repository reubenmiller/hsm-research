# golang http client

## Example

```sh
go run main.go | jq
```

**Output**

```json
Status: 200 OK
{
  "HTTPS": "on",
  "SSL_SERVER_S_DN_CN": "certauth.cryptomix.com",
  "SSL_SERVER_I_DN_C": "US",
  "SSL_SERVER_I_DN_O": "Let's Encrypt",
  "SSL_SERVER_I_DN_CN": "R10",
  "SSL_CLIENT_S_DN_OU": "Test Device",
  "SSL_CLIENT_S_DN_O": "Thin Edge",
  "SSL_CLIENT_S_DN_CN": "rmi_macos01",
  "SSL_CLIENT_I_DN_OU": "Test Device",
  "SSL_CLIENT_I_DN_O": "Thin Edge",
  "SSL_CLIENT_I_DN_CN": "rmi_macos01",
  "SSL_SERVER_SAN_DNS_0": "certauth.cryptomix.com",
  "SSL_VERSION_INTERFACE": "mod_ssl/2.4.41",
  "SSL_VERSION_LIBRARY": "OpenSSL/1.1.1f",
  "SSL_PROTOCOL": "TLSv1.3",
  "SSL_SECURE_RENEG": "false",
  "SSL_COMPRESS_METHOD": "NULL",
  "SSL_CIPHER": "TLS_AES_256_GCM_SHA384",
  "SSL_CIPHER_EXPORT": "false",
  "SSL_CIPHER_USEKEYSIZE": "256",
  "SSL_CIPHER_ALGKEYSIZE": "256",
  "SSL_CLIENT_VERIFY": "FAILED:self signed certificate",
  "SSL_CLIENT_M_VERSION": "3",
  "SSL_CLIENT_M_SERIAL": "01001979B3F0E1593C052D35AD0D48245BBBDF93",
  "SSL_CLIENT_V_START": "Jan 10 13:50:40 2025 GMT",
  "SSL_CLIENT_V_END": "Jan 10 13:50:40 2026 GMT",
  "SSL_CLIENT_V_REMAIN": "365",
  "SSL_CLIENT_S_DN": "CN=rmi_macos01,O=Thin Edge,OU=Test Device",
  "SSL_CLIENT_I_DN": "CN=rmi_macos01,O=Thin Edge,OU=Test Device",
  "SSL_CLIENT_A_KEY": "rsaEncryption",
  "SSL_CLIENT_A_SIG": "sha256WithRSAEncryption",
  "SSL_CLIENT_CERT_RFC4523_CEA": "{ serialNumber 5711209991321064067544332534630904546438406035, issuer rdnSequence:\"CN=rmi_macos01,O=Thin Edge,OU=Test Device\" }",
  "SSL_SERVER_M_VERSION": "3",
  "SSL_SERVER_M_SERIAL": "042EA479A1D286DFFD9076F0782A0AE39822",
  "SSL_SERVER_V_START": "Dec 27 02:04:53 2024 GMT",
  "SSL_SERVER_V_END": "Mar 27 02:04:52 2025 GMT",
  "SSL_SERVER_S_DN": "CN=certauth.cryptomix.com",
  "SSL_SERVER_I_DN": "CN=R10,O=Let's Encrypt,C=US",
  "SSL_SERVER_A_KEY": "rsaEncryption",
  "SSL_SERVER_A_SIG": "sha256WithRSAEncryption",
  "SSL_SESSION_ID": "edadb3a8440efc50788760bf350740244876d0858ea4fe4f698d36ed8951bedd",
  "SSL_SESSION_RESUMED": "Initial",
  "HTTP_HOST": "certauth.cryptomix.com",
  "HTTP_USER_AGENT": "Go-http-client/1.1",
  "HTTP_ACCEPT_ENCODING": "gzip",
  "SERVER_SIGNATURE": "",
  "SERVER_SOFTWARE": "Apache",
  "SERVER_NAME": "certauth.cryptomix.com",
  "SERVER_ADDR": "62.210.201.125",
  "SERVER_PORT": "443",
  "REMOTE_ADDR": "93.230.25.126",
  "REQUEST_SCHEME": "https",
  "REMOTE_PORT": "55846",
  "GATEWAY_INTERFACE": "CGI/1.1",
  "SERVER_PROTOCOL": "HTTP/1.1",
  "REQUEST_METHOD": "GET",
  "QUERY_STRING": "",
  "REQUEST_URI": "/json/",
  "REQUEST_TIME_FLOAT": 1736523674.507,
  "REQUEST_TIME": 1736523674
}
```
