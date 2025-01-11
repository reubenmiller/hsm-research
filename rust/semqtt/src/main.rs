//! Example of how to configure rumqttd to connect to a server using TLS and authentication.
use std::{error::Error};

use rumqttc::{AsyncClient, MqttOptions, TlsConfiguration, Transport};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();
    color_backtrace::install();

    let mut mqttoptions = MqttOptions::new("rmi_macos01", "thin-edge-io.eu-latest.cumulocity.com", 8883);
    mqttoptions.set_keep_alive(std::time::Duration::from_secs(60));

    // Dummies to prevent compilation error in CI
    let ca = include_bytes!("/opt/homebrew/etc/ca-certificates/cert.pem");
    let client_cert = include_bytes!("/opt/homebrew/etc/tedge/device-certs/tedge-certificate.pem");
    let client_key = include_bytes!("/opt/homebrew/etc/tedge/device-certs/tedge-private-key.pem");

    let transport = Transport::Tls(TlsConfiguration::Simple {
        ca: ca.into(),
        alpn: None,
        client_auth: Some((client_cert.into(), client_key.into())),
    });

    mqttoptions.set_transport(transport);

    let (_client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

    _client.subscribe("s/ds", rumqttc::QoS::AtLeastOnce).await?;
    _client.publish("s/us", rumqttc::QoS::AtLeastOnce, false, "500").await?;

    loop {
        match eventloop.poll().await {
            Ok(v) => {
                println!("Event = {v:?}");
            }
            Err(e) => {
                println!("Error = {e:?}");
                break;
            }
        }
    }

    Ok(())
}