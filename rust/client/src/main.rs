//! Example of how to configure rumqttc to connect to a server using TLS and authentication.
//! Source https://github.com/leonardodepaula/Cryptoki-TLS
//! https://github.com/rustls/rustls-cng/blob/dev/src/signer.rs

use std::error::Error;
use std::sync::{Arc, Mutex};
use log;

use asn1_rs::ToDer;
use base64::prelude::*;
use cryptoki::object::KeyType;
use der::asn1::{AnyRef, ObjectIdentifier};
use der::Sequence;
use rumqttc::tokio_rustls::rustls::ClientConfig;
use tokio;

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::{
        rsa::{PkcsMgfType, PkcsPssParams},
        Mechanism, MechanismType,
    },
    object::{Attribute, AttributeType, CertificateType, ObjectClass},
    session::{Session, UserType},
    types::AuthPin,
};

// Only used when loading certs from file
#[allow(unused_imports)]
use rumqttc::tokio_rustls::rustls::pki_types::pem::PemObject;

use rumqttc::{AsyncClient, MqttOptions};

use rumqttc::tokio_rustls::rustls::{
    client::ResolvesClientCert,
    pki_types::CertificateDer,
    sign::{CertifiedKey, Signer, SigningKey},
    Error as RusTLSError, SignatureAlgorithm, SignatureScheme,
};

use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Clone)]
struct PKCS11 {
    session: Arc<Mutex<Session>>,
}

#[derive(Debug)]
struct PkcsSigner {
    pkcs11: PKCS11,
    scheme: SignatureScheme,
}

impl PkcsSigner {
    fn get_mechanism(&self) -> anyhow::Result<Mechanism, RusTLSError> {
        log::debug!("Getting mechanism from chosen scheme: {:?}", self.scheme);
        match self.scheme {
            SignatureScheme::ED25519 => Ok(Mechanism::Eddsa),
            SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(Mechanism::EcdsaSha256),
            SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(Mechanism::EcdsaSha384),
            SignatureScheme::ECDSA_NISTP521_SHA512 => Ok(Mechanism::EcdsaSha512),
            SignatureScheme::RSA_PKCS1_SHA1 => Ok(Mechanism::Sha1RsaPkcs),
            SignatureScheme::RSA_PKCS1_SHA256 => Ok(Mechanism::Sha256RsaPkcs),
            SignatureScheme::RSA_PKCS1_SHA384 => Ok(Mechanism::Sha384RsaPkcs),
            SignatureScheme::RSA_PKCS1_SHA512 => Ok(Mechanism::Sha512RsaPkcs),
            SignatureScheme::RSA_PSS_SHA256 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA256_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA256,
                    s_len: 32.into(),
                };
                Ok(Mechanism::Sha256RsaPkcsPss(params))
            }
            SignatureScheme::RSA_PSS_SHA384 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA384_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA384,
                    s_len: 48.into(),
                };
                Ok(Mechanism::Sha384RsaPkcsPss(params))
            }
            SignatureScheme::RSA_PSS_SHA512 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA512_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA512,
                    s_len: 64.into(),
                };
                Ok(Mechanism::Sha512RsaPkcsPss(params))
            }
            _ => Err(RusTLSError::General(
                "Unsupported signature scheme".to_owned(),
            )),
        }
    }
}

fn write_asn1_integer(writer: &mut dyn std::io::Write, b: &[u8]) {
    let mut i = asn1_rs::BigInt::from_signed_bytes_be(&b);
    if i.sign() == asn1_rs::Sign::Minus {
        // Prepend a most significant zero byte if value < 0
        let mut positive = b.to_vec();
        positive.insert(0, 0);

        i = asn1_rs::BigInt::from_signed_bytes_be(&positive);
    }
    let i = i.to_signed_bytes_be();
    let i = asn1_rs::Integer::new(&i);
    let _ = i.write_der(writer);
}

fn format_asn1_ecdsa_signature(
    r_bytes: &[u8],
    s_bytes: &[u8],
) -> Result<Vec<u8>, der::Error> {
    let mut writer = Vec::new();

    write_asn1_integer(&mut writer, r_bytes);

    write_asn1_integer(&mut writer, s_bytes);

    let seq = asn1_rs::Sequence::new(writer.into());
    let b = seq.to_der_vec().unwrap();
    log::debug!("Encoded ASN.1 Der: {:?}", BASE64_STANDARD_NO_PAD.encode(&b));
    Ok(b)
}

impl Signer for PkcsSigner {
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>, RusTLSError> {
        let session = self.pkcs11.session.lock().unwrap();

        let key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
        ];

        let key = session
            .find_objects(&key_template)
            .unwrap()
            .into_iter()
            .nth(0)
            .unwrap();

        let mechanism = self.get_mechanism().unwrap();

        let (mechanism, digest_mechanism) = match mechanism {
            Mechanism::EcdsaSha256 => (Mechanism::Ecdsa, Some(Mechanism::Sha256)),
            Mechanism::EcdsaSha384 => (Mechanism::Ecdsa, Some(Mechanism::Sha384)),
            Mechanism::EcdsaSha512 => (Mechanism::Ecdsa, Some(Mechanism::Sha512)),
            Mechanism::Sha1RsaPkcs => (Mechanism::RsaPkcs, Some(Mechanism::Sha1)),
            Mechanism::Sha256RsaPkcs => (Mechanism::RsaPkcs, Some(Mechanism::Sha256)),
            Mechanism::Sha384RsaPkcs => (Mechanism::RsaPkcs, Some(Mechanism::Sha384)),
            Mechanism::Sha512RsaPkcs => (Mechanism::RsaPkcs, Some(Mechanism::Sha512)),
            _ => {
                log::warn!("Warning: Unsupported mechanism, trying it out anyway. value={mechanism:?}");
                (Mechanism::Ecdsa, Some(Mechanism::Sha256))
            },
        };

        log::debug!(
            "Input message ({:?}): {:?}",
            mechanism,
            String::from_utf8_lossy(&message)
        );

        let direct_sign = digest_mechanism.is_none();
        log::debug!("Direct sign: {direct_sign:?}");

        let signature_raw = if direct_sign {
            log::debug!(
                "Signing message (len={:?}):\n{:?}",
                message.len(),
                BASE64_STANDARD_NO_PAD.encode(&message)
            );
            let signature_raw = match session.sign(&mechanism, key, &message) {
                Ok(result) => result,
                Err(err) => {
                    log::error!("Failed to sign: {err:?}");
                    "".into()
                }
            };
            signature_raw
        } else {
            let digest = session.digest(&digest_mechanism.unwrap(), &message).unwrap();
            session.sign(&mechanism, key, &digest).unwrap()
        };

        // Split raw signature into r and s values (assuming 32 bytes each)
        log::debug!("Signature (raw) len={:?}", signature_raw.len());
        let r_bytes = signature_raw[0..32].to_vec();
        let s_bytes = signature_raw[32..].to_vec();
        let signature_asn1 = format_asn1_ecdsa_signature(&r_bytes, &s_bytes).unwrap();
        log::debug!("Encoded ASN.1 Signature: len={:?} {:?}", signature_asn1.len(), signature_asn1);
        Ok(signature_asn1)
    }

    fn scheme(&self) -> SignatureScheme {
        log::info!("Using Signature scheme: {:?}", self.scheme.as_str());
        self.scheme
    }
}

#[derive(Debug)]
struct ECSigningKey {
    pkcs11: PKCS11,
}

impl ECSigningKey {
    fn supported_schemes(&self) -> &[SignatureScheme] {
        &[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

impl SigningKey for ECSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        log::debug!("Offered signature schemes. offered={:?}", offered);
        let supported = self.supported_schemes();
        for scheme in offered {
            if supported.contains(scheme) {
                log::debug!("Matching scheme: {:?}", scheme.as_str());
                return Some(Box::new(PkcsSigner {
                    pkcs11: self.pkcs11.clone(),
                    scheme: *scheme,
                }));
            }
        }
        log::error!(
            "Could not find a matching signing scheme. offered={:?}",
            offered
        );
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

//
// RSA Signer
//
#[derive(Debug)]
struct RSASigningKey {
    pkcs11: PKCS11,
}

impl RSASigningKey {
    fn supported_schemes(&self) -> &[SignatureScheme] {
        &[
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

impl SigningKey for RSASigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        log::debug!("Offered signature schemes. offered={:?}", offered);
        let supported = self.supported_schemes();
        for scheme in offered {
            if supported.contains(scheme) {
                log::debug!("Matching scheme: {:?}", scheme.as_str());
                return Some(Box::new(PkcsSigner {
                    pkcs11: self.pkcs11.clone(),
                    scheme: *scheme,
                }));
            }
        }
        log::debug!(
            "Could not find a matching signing scheme. offered={:?}",
            offered
        );
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct ClientCertResolver {
    chain: Vec<CertificateDer<'static>>,
    signing_key: Arc<dyn SigningKey>,
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::new(CertifiedKey {
            cert: self.chain.clone(),
            key: self.signing_key.clone(),
            ocsp: None,
        }))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn get_key_type(
    pkcs11: PKCS11,
) -> KeyType {
    let session = pkcs11.session.lock().unwrap();

        let key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
        ];

        let key = session
            .find_objects(&key_template)
            .unwrap()
            .into_iter()
            .nth(0)
            .unwrap();

        let info = session.get_attributes(
            key,
            &[
                AttributeType::KeyType,
            ],
        );
        let mut key_type = KeyType::EC;
        match info {
            Ok(value) => {
                for v in &value[0..value.len()] {
                    match v {
                        Attribute::KeyType(raw_value) => {
                            key_type = raw_value.clone();
                        },
                        _ => {
                            log::warn!("Could not read attribute value: {:?}", v);
                        }
                    }
                }
            }
            Err(err) => log::warn!("Could not read value: {err:?}"),
        };

        key_type
}

fn get_certificate_der(
    pkcs11: PKCS11,
) -> anyhow::Result<Vec<CertificateDer<'static>>, anyhow::Error> {
    let session = pkcs11.session.lock().unwrap();
    let search_template = vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
    ];
    let handle = session.find_objects(&search_template)?.remove(0);
    let value = session
        .get_attributes(handle, &[AttributeType::Value])?
        .remove(0);

    // Print out info about the certificate
    match value {
        Attribute::Value(cert) => {
            log::trace!("Certificate: {:?}", CertificateDer::from_slice(&cert));

            let res = X509Certificate::from_der(&cert);
            match res {
                Ok((_rem, cert)) => {
                    let cn = cert.subject().iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok());
                    if let Some(cn) = cn {
                        log::info!("Common Name: {:?}", cn);
                    }
                    log::info!("Subject: {:?}", cert.subject().to_string());
                    log::info!("Issuer: {:?}", cert.issuer().to_string());
                    log::info!("Serial: {:?}", cert.raw_serial_as_string().replace(":", ""));
                }
                _ => panic!("x509 parsing failed: {:?}", res),
            }

            let certificate_der = CertificateDer::from_slice(&cert).into_owned();
            Ok(vec![certificate_der])
        }
        _ => {
            anyhow::bail!("Couldn't find X509 certificate.")
        }
    }
}

fn get_certificate_common_name(c: CertificateDer<'static>) -> String {
    let res = X509Certificate::from_der(&c);
    match res {
        Ok((_rem, cert)) => {
            let cn = cert.subject().iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok());
            cn.unwrap().to_string()
        }
        _ => "".to_string(),
    }
}

fn get_env_var(keys: Vec<&str>, default_value: &str) -> String {
    let value = keys.iter().map(|key| std::env::var(key).ok()).skip_while(|value| !value.is_some()).next().unwrap_or(Some(default_value.to_string()));
    value.unwrap_or(default_value.to_string())
}


#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    match std::env::var("RUST_LOG") {
        Ok(_) => pretty_env_logger::init(),
        _ => pretty_env_logger::formatted_builder().filter_level(log::LevelFilter::Info).init(),
    }

    // pretty_env_logger::init();
    color_backtrace::install();

    log::info!("Starting Test MQTT Client with PKCS#11 support enabled");


    let pkcs11_module = get_env_var(vec!["PKCS11_MODULE"], "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so");
    let pkcs11_client = Pkcs11::new(pkcs11_module.clone())?;
    pkcs11_client.initialize(CInitializeArgs::OsThreads)?;

    let slot = pkcs11_client.get_slots_with_token()?.remove(0);
    let session = pkcs11_client.open_ro_session(slot)?;

    let pkcs11_pin = get_env_var(vec!["PKCS11_PIN", "GNUTLS_PIN"], "123456");
    log::info!(
        "Logging into HSM using PKCS#11: module={:?}",
        pkcs11_module,
    );
    session.login(UserType::User, Some(&AuthPin::new(pkcs11_pin.into())))?;

    let pkcs11 = PKCS11 {
        session: Arc::new(Mutex::new(session)),
    };
    let chain = get_certificate_der(pkcs11.clone())?;

    let mqtt_client_id = get_certificate_common_name(chain[0].clone());

    let key_type = get_key_type(pkcs11.clone());
    log::info!("Key Type: {:?}", key_type.to_string());
    let client_cert_resolver = match key_type {
        KeyType::EC => {
            Arc::new(ClientCertResolver {
                chain: chain,
                signing_key: Arc::new(ECSigningKey { pkcs11 }),
            })
        },
        KeyType::RSA => {
            Arc::new(ClientCertResolver {
                chain: chain,
                signing_key: Arc::new(RSASigningKey { pkcs11 }),
            })
        },
        _ => {
            panic!("Unsupported key type. Only EC and RSA keys are supported");
        },
    };

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
        .with_client_cert_resolver(client_cert_resolver);

    let c8y_domain = get_env_var(vec!["TEDGE_C8Y_URL", "C8Y_DOMAIN", "C8Y_HOST", "C8Y_URL"], "thin-edge-io.eu-latest.cumulocity.com");
    let c8y_domain = c8y_domain.replace("https://", "").replace("http://", "");

    log::info!("----------------------------------------------------------------------------------------------------");
    log::info!(
        "Starting MQTT Test Client: client_id={:?}, domain={:?}",
        mqtt_client_id, c8y_domain
    );
    log::info!("----------------------------------------------------------------------------------------------------");
    let mut mqttoptions = MqttOptions::new(mqtt_client_id, c8y_domain, 8883);
    mqttoptions.set_keep_alive(std::time::Duration::from_secs(60));

    mqttoptions.set_transport(rumqttc::Transport::tls_with_config(client_config.into()));

    let (_client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

    _client.subscribe("s/ds", rumqttc::QoS::AtLeastOnce).await?;
    _client
        .publish("s/us", rumqttc::QoS::AtLeastOnce, false, "500")
        .await?;

    loop {
        match eventloop.poll().await {
            Ok(v) => {
                log::info!("Event = {v:?}");
            }
            Err(e) => {
                log::error!("Error = {e:?}");
                break;
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_client_cert_signer() {
    let pkcs11module = std::env::var("PKCS11_MODULE");
    let pkcs11module = pkcs11module
        .as_deref()
        .unwrap_or("/opt/homebrew/lib/pkcs11/opensc-pkcs11.so");
    let pkcs11client = Pkcs11::new(pkcs11module).unwrap();
    pkcs11client.initialize(CInitializeArgs::OsThreads).unwrap();

    let slot = pkcs11client.get_slots_with_token().unwrap().remove(0);
    let session = pkcs11client.open_ro_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new("123456".into())))
        .unwrap();

    let pkcs11 = PKCS11 {
        session: Arc::new(Mutex::new(session)),
    };

    let my_signing_key = Arc::new(ECSigningKey { pkcs11 });

    let signer = my_signing_key
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .unwrap();
    let message = BASE64_URL_SAFE.decode("ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIGNsaWVudCBDZXJ0aWZpY2F0ZVZlcmlmeQB9DNs6ZTjv4f9ZhZey1JPUztq_LkyONGNk3CqebzDF6w==").unwrap();
    let sig = signer.sign(&message).unwrap();

    assert_eq!(
        "rSM44KL7ndqH6sC574bsUjsi86onRHoW3z8ozPSHYRw",
        BASE64_URL_SAFE.encode(sig)
    );

    let _ = sig;
}

#[tokio::test]
async fn test_parse_interger_as_bigint() {
    let signature_raw: [u8; 64] = [
        12, 134, 45, 206, 14, 82, 48, 131, 85, 107, 153, 242, 215, 171, 6, 95, 142, 115, 115, 163,
        233, 43, 57, 20, 244, 20, 185, 217, 57, 50, 121, 119, 127, 224, 225, 70, 120, 77, 108, 126,
        30, 76, 174, 27, 162, 233, 163, 127, 20, 79, 215, 131, 117, 135, 240, 208, 52, 54, 215,
        168, 170, 142, 67, 150,
    ];

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let r = asn1_rs::Integer::new(&r_bytes);
    let s = asn1_rs::Integer::new(&s_bytes);

    let r = r.as_bigint();
    let s = s.as_bigint();

    assert_eq!(
        "5664827823522302053252121256142066174752445323573986797468973731770988132727",
        r.to_string()
    );
    assert_eq!(
        "57841060305378809294557622035767714131062944761800257564159872864525742916502",
        s.to_string()
    );
}

/// X.509 `AlgorithmIdentifier`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier<'a> {
    /// This field contains an ASN.1 `OBJECT IDENTIFIER`, a.k.a. OID.
    pub algorithm: ObjectIdentifier,

    /// This field is `OPTIONAL` and contains the ASN.1 `ANY` type, which
    /// in this example allows arbitrary algorithm-defined parameters.
    pub parameters: Option<AnyRef<'a>>,
}

#[test]
fn test_signature_encoding_case1() {
    // case 1: golang has prefixed 0x00 values in the r and s values, length is 33 bytes (not 32!)
    let signature_raw: [u8; 64] = [
        142, 102, 8, 28, 159, 10, 211, 68, 100, 17, 39, 6, 113, 189, 132, 21, 20, 139, 55, 179, 45,
        35, 209, 13, 187, 34, 44, 216, 5, 95, 43, 108, 129, 152, 120, 162, 93, 233, 183, 149, 115,
        106, 113, 154, 89, 13, 62, 42, 168, 3, 193, 181, 31, 59, 41, 199, 153, 64, 167, 39, 2, 65,
        80, 77,
    ];
    let golang_output = String::from("MEYCIQCOZggcnwrTRGQRJwZxvYQVFIs3sy0j0Q27IizYBV8rbAIhAIGYeKJd6beVc2pxmlkNPiqoA8G1Hzspx5lApycCQVBN");

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let sig_encoded = format_asn1_ecdsa_signature(&r_bytes, &s_bytes).unwrap();
    let rust_output = BASE64_STANDARD_NO_PAD.encode(sig_encoded);

    assert_eq!(rust_output, golang_output);
}

#[test]
fn test_signature_encoding_case2() {
    // case 2: golang does not have prefixed 0x00 values in r and s values, length is 32 bytes
    let signature_raw: [u8; 64] = [219, 150, 112, 172, 136, 180, 34, 225, 237, 161, 182, 149, 20, 205, 205, 229, 59, 48, 205, 56, 235, 77, 93, 38, 197, 93, 192, 27, 118, 121, 76, 10, 127, 190, 158, 234, 246, 105, 89, 61, 238, 3, 248, 100, 31, 64, 218, 242, 175, 75, 12, 197, 255, 164, 230, 145, 129, 182, 237, 93, 106, 217, 166, 219];
    let golang_output: [u8; 71] = [48, 69, 2, 33, 0, 219, 150, 112, 172, 136, 180, 34, 225, 237, 161, 182, 149, 20, 205, 205, 229, 59, 48, 205, 56, 235, 77, 93, 38, 197, 93, 192, 27, 118, 121, 76, 10, 2, 32, 127, 190, 158, 234, 246, 105, 89, 61, 238, 3, 248, 100, 31, 64, 218, 242, 175, 75, 12, 197, 255, 164, 230, 145, 129, 182, 237, 93, 106, 217, 166, 219];

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let sig_encoded = format_asn1_ecdsa_signature(&r_bytes, &s_bytes).unwrap();

    assert_eq!(format!("{:x?}", sig_encoded) , format!("{:x?}", golang_output));
}
