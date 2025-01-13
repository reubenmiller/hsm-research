//! Example of how to configure rumqttd to connect to a server using TLS and authentication.
//! Source https://github.com/leonardodepaula/Cryptoki-TLS
//! https://github.com/rustls/rustls-cng/blob/dev/src/signer.rs
use std::error::Error;

use rumqttc::tokio_rustls::rustls::ClientConfig;

// Only used when loading certs from file
use rumqttc::tokio_rustls::rustls::pki_types::pem::PemObject;

use rumqttc::{AsyncClient, MqttOptions};

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::{
        Mechanism, MechanismType,
        rsa::{PkcsMgfType, PkcsPssParams}
    },
    object::{Attribute, AttributeType, CertificateType, ObjectClass},
    session::{UserType, Session},
    types::AuthPin,
};
// use hyper_rustls::ConfigBuilderExt;
// use reqwest;
use rumqttc::tokio_rustls::rustls::{
    Error as RusTLSError, SignatureAlgorithm, SignatureScheme,
    client::ResolvesClientCert,
    pki_types::CertificateDer,
    sign::{CertifiedKey, Signer, SigningKey},
};
use x509_parser::prelude::{FromDer, X509Certificate};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct PKCS11 {
    session: Arc<Mutex<Session>>,
}

#[derive(Debug)]
struct MySigner {
    pkcs11: PKCS11,
    scheme: SignatureScheme
}

impl MySigner {
    fn get_mechanism(&self) -> anyhow::Result<Mechanism, RusTLSError> {
        match self.scheme {
            SignatureScheme::ED25519 => Ok(Mechanism::Eddsa),
            SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(Mechanism::EcdsaSha256),
            SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(Mechanism::EcdsaSha384),
            SignatureScheme::ECDSA_NISTP521_SHA512 => Ok(Mechanism::EcdsaSha512),
            SignatureScheme::RSA_PKCS1_SHA256 => Ok(Mechanism::Sha256RsaPkcs),
            SignatureScheme::RSA_PKCS1_SHA384 => Ok(Mechanism::Sha384RsaPkcs),
            SignatureScheme::RSA_PKCS1_SHA512 => Ok(Mechanism::Sha512RsaPkcs),
            SignatureScheme::RSA_PSS_SHA256 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA256_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA256,
                    s_len: 32.into()
                };
                Ok(Mechanism::Sha256RsaPkcsPss(params))
            },
            SignatureScheme::RSA_PSS_SHA384 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA384_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA384,
                    s_len: 48.into()
                };
                Ok(Mechanism::Sha384RsaPkcsPss(params))
            },
            SignatureScheme::RSA_PSS_SHA512 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA512_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA512,
                    s_len: 64.into()
                };
                Ok(Mechanism::Sha512RsaPkcsPss(params))
            },
            _ => Err(RusTLSError::General("Unsupported signature scheme".to_owned())),
        }
    }
}

impl Signer for MySigner {
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>, RusTLSError> {

        let session = self.pkcs11.session.lock().unwrap();

        let key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            // Attribute::KeyType(KeyType::EC),
        ];
    
        let key = session
            .find_objects(&key_template).unwrap()
            .into_iter()
            .nth(0)
            .unwrap();
    
        let info = session.get_attributes(key, &[
            AttributeType::Id,
            AttributeType::Class,
            AttributeType::AcIssuer,
            AttributeType::Application,
            AttributeType::Label,
            AttributeType::Coefficient,
            AttributeType::KeyType,
            AttributeType::Issuer,
            AttributeType::Url,
        ]);
        println!("");
        match info {
            Ok(value) => {
                for v in &value[0..value.len() - 1] {
                    
                    match v {
                        Attribute::Application(raw_value) => println!("Private Key Application: {:?}",  String::from_utf8_lossy(raw_value)),
                        Attribute::Label(raw_value) => println!("Private Key Label: {:?}",  String::from_utf8_lossy(raw_value)),
                        Attribute::Id(raw_value) => println!("Private Key Id: {:?}",  String::from_utf8_lossy(raw_value)),
                        Attribute::Issuer(raw_value) => println!("Private Key Issuer: {:?}",  String::from_utf8_lossy(raw_value)),
                        Attribute::Url(raw_value) => println!("Private Key URL: {:?}",  String::from_utf8_lossy(raw_value)),
                        Attribute::Class(raw_value) => println!("Private Key Class: {:?}",  raw_value.to_string()),
                        _ => {
                            println!("Could not read attribute value: {:?}", v);
                        },
                    }
                }
            },
            Err(err) => println!("Could not read value: {err:?}"),
        };
        // info

        let mechanism = self.get_mechanism().unwrap();

        let signed_message = match session.sign(&mechanism, key, message) {
            Ok(result) => {
                println!("Signed data: {:?}", String::from_utf8_lossy(&result));
                result
            },
            Err(err) => {
                println!("Failed to sign: {err:?}");
                "".into()
            },
        };
        Ok(signed_message)
    }

    fn scheme(&self) -> SignatureScheme {
        println!("Using scheme: {:?}", self.scheme.as_str());
        self.scheme
    }
}

#[derive(Debug)]
struct MySigningKey {
    pkcs11: PKCS11

}

impl MySigningKey {
    fn supported_schemes(&self) -> &[SignatureScheme] {
        &[
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

impl SigningKey for MySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let supported = self.supported_schemes();
        for scheme in offered {
            if supported.contains(scheme) {
                println!("Matching scheme: {:?}", scheme.as_str());
                return Some(Box::new(MySigner { pkcs11: self.pkcs11.clone(), scheme: *scheme }));
            }
        }
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
        // SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct ClientCertResolver {
    chain: Vec<CertificateDer<'static>>,
    signing_key: Arc<MySigningKey>,
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(&self, _acceptable_issuers: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(Arc::new(CertifiedKey {cert: self.chain.clone(), key: self.signing_key.clone(), ocsp: None}))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn get_certificate_der(pkcs11: PKCS11) -> anyhow::Result<Vec<CertificateDer<'static>>, anyhow::Error> {
    let session = pkcs11.session.lock().unwrap();
    let search_template = vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
    ];
    let handle = session.find_objects(&search_template)?.remove(0);
    let value = session.get_attributes(handle, &[AttributeType::Value])?.remove(0);

    
    // Print out info about the certificate
    match value {
        Attribute::Value(cert) => {
            println!("Certificate: {:?}",  CertificateDer::from_slice(&cert));

            let res = X509Certificate::from_der(&cert);
            match res {
                Ok((_rem, cert)) => {
                    println!("Public Key: {:?}", cert.public_key().algorithm.algorithm.to_string());
                    println!("Subject: {:?}", cert.subject().to_string());
                    println!("Issuer: {:?}", cert.issuer().to_string());
                    println!("Serial: {:?}", cert.raw_serial_as_string().replace(":", ""));
                },
                _ => panic!("x509 parsing failed: {:?}", res),
            }

            let certificate_der = CertificateDer::from_slice(&cert).into_owned();
            Ok(vec![certificate_der])
        },
        _ => {
            anyhow::bail!("Couldn't find X509 certificate.")
        },
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();
    color_backtrace::install();

    // Alternative module: /opt/homebrew/lib/pkcs11/opensc-pkcs11.so
    let pkcs11module = std::env::var("PKCS11_MODULE");
    let pkcs11module = pkcs11module.as_deref().unwrap_or("/opt/homebrew/lib/pkcs11/opensc-pkcs11.so");
    let pkcs11client = Pkcs11::new(pkcs11module)?;
    pkcs11client.initialize(CInitializeArgs::OsThreads)?;

    let slot = pkcs11client.get_slots_with_token()?.remove(0);
    let session = pkcs11client.open_ro_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new("123456".into())))?;

    // Debug
    let search = vec![Attribute::Class(ObjectClass::CERTIFICATE), Attribute::CertificateType(CertificateType::X_509)];
    for handle in session.find_objects(&search)? {
        // each cert: get the "value" which will be the raw certificate data
        for value in session.get_attributes(handle, &[AttributeType::SerialNumber])? {
           if let Attribute::Value(value) = value {
                match String::from_utf8(value) {
                    Ok(path) => println!("Certificate value: {:?}", path),
                    Err(e) => println!("Invalid UTF-8 sequence: {}", e),
                };
           }
        }
    }

    let pkcs11 = PKCS11 { session: Arc::new(Mutex::new(session)) };
    let chain = get_certificate_der(pkcs11.clone())?;
    let my_signing_key = Arc::new(MySigningKey { pkcs11 });


    let mut root_cert_store = rumqttc::tokio_rustls::rustls::RootCertStore::empty();
    root_cert_store.add_parsable_certificates(
        rustls_native_certs::load_native_certs().expect("could not load platform certs"),
    );

    // Alternative: Create client using file based certs (without using HSM)
    // let client_cert = rumqttc::tokio_rustls::rustls::pki_types::CertificateDer::from_pem_file("/opt/homebrew/etc/tedge/device-certs/tedge-certificate.pem")?;
    // let client_key = rumqttc::tokio_rustls::rustls::pki_types::PrivateKeyDer::from_pem_file("/opt/homebrew/etc/tedge/device-certs/tedge-private-key.pem")?;
    // let client_config = ClientConfig::builder()
    //     .with_root_certificates(root_cert_store)
    //     .with_client_auth_cert(chain, client_key)?;

    // Create client using custom client cert resolver
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_cert_resolver(Arc::new(ClientCertResolver {
            chain: chain,
            signing_key: my_signing_key,
        }));

    let mqtt_client_id = std::env::var("DEVICE_ID");
    let mqtt_client_id = mqtt_client_id.as_deref().unwrap_or("rmi_macos01");

    let c8y_domain = std::env::var("C8Y_DOMAIN");
    let c8y_domain = c8y_domain.as_deref().unwrap_or("thin-edge-io.eu-latest.cumulocity.com");

    let mut mqttoptions = MqttOptions::new(mqtt_client_id, c8y_domain, 8883);
    mqttoptions.set_keep_alive(std::time::Duration::from_secs(60));

    mqttoptions.set_transport(rumqttc::Transport::tls_with_config(client_config.into()));

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