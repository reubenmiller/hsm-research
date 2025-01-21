//! Example of how to configure rumqttd to connect to a server using TLS and authentication.
//! Source https://github.com/leonardodepaula/Cryptoki-TLS
//! https://github.com/rustls/rustls-cng/blob/dev/src/signer.rs
use std::error::Error;
use std::hash::Hash;
use std::io::{Read, Write};

use asn1_rs::nom::AsBytes;
use base64::prelude::*;

use asn1_rs::{Integer, FromBer, ToDer};

use tokio;

// use der::Encode;
use rumqttc::tokio_rustls::rustls::ClientConfig;
// use der;
// use asn1::{Sequence, SimpleAsn1Readable};
// use aws_lc_rs::signature::{Signature};
use ecdsa::Signature;
// use der::asn1::{Sequence}; // Corrected import
use asn1::{self, BigUint, SimpleAsn1Readable};

use der::{asn1::{AnyRef, ObjectIdentifier}, Encode, Decode};
use der::Sequence;

use num_bigint::{BigInt, Sign, ToBigInt, ToBigUint};


use simple_asn1::{self, der_decode, oid, ASN1Block};
use simple_asn1::ToASN1;

// use asn1::Asn1Write

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
// use tokio_rustls::rustls::SignatureAlgorithm;
// use x509_parser::der_parser::asn1_rs::ToDer;
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
        println!("Getting mechanism from chosen scheme: {:?}", self.scheme);
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

fn prepend<T>(v: Vec<T>, s: &[T]) -> Vec<T>
where
    T: Clone,
{
    let mut tmp: Vec<_> = s.to_owned();
    tmp.extend(v);
    tmp
}



fn create_der_ecdsa_signature_using_bigint(r_bytes: &[u8], s_bytes: &[u8]) -> Result<Vec<u8>, der::Error> {
    let mut writer = Vec::new();

    // TODO: Is a header missing?
    // let obj = asn1_rs::oid!("1234");

    let r = asn1_rs::Integer::new(r_bytes);
    r.write_der(&mut writer);

    let s = asn1_rs::Integer::new(s_bytes);
    s.write_der(&mut writer);

    let seq = asn1_rs::Sequence::new(writer.into());
    // let seq = asn1_rs::Sequence::new(writer.into());

    let b = seq.to_der_vec().unwrap();

    println!("Created der: {:?}", BASE64_STANDARD_NO_PAD.encode(&b));
    Ok(b)
    

    // let r = asn1_rs::Integer::from(r);

    // let r = asn1_rs::Integer::from_ber(r_bytes).expect("serialization error");
    // let s = asn1_rs::Integer::from_ber(s_bytes).expect("serialization error");

    // let r = parse_rs(r_bytes);
    // let s = parse_rs(s_bytes);

    // let (_, r) = &r.to_bytes_be();
    // let (_, s) = &s.to_bytes_be();

    // let result = asn1::write(|w| {
    //     w.write_element(&asn1::SequenceWriter::new(&|w| {
    //         w.write_element(&r.as_bytes())?;
    //         w.write_element(&s.as_bytes())?;
    //         Ok(())
    //     }))
    // });
    // let result = result.unwrap();
    // Ok(result)
}


fn create_der_ecdsa_signature_using_biguint(r_bytes: &[u8], s_bytes: &[u8]) -> Result<Vec<u8>, der::Error> {
    let r = num_bigint::BigUint::from_bytes_be(r_bytes);
    let s = num_bigint::BigUint::from_bytes_le(s_bytes);

    let r = r.to_bigint().unwrap();
    let s = s.to_bigint().unwrap();

    let (_, r) = &r.to_bytes_be();
    let (_, s) = &s.to_bytes_be();

    let result = asn1::write(|w| {
        w.write_element(&asn1::SequenceWriter::new(&|w| {
            w.write_element(&r.as_bytes())?;
            w.write_element(&s.as_bytes())?;
            Ok(())
        }))
    });
    let result = result.unwrap();
    Ok(result)
}

fn create_der_ecdsa_signature(r_bytes: &[u8], s_bytes: &[u8]) -> Result<Vec<u8>, der::Error> {
    // let (_, r) = Integer::from_ber(r_bytes).unwrap();
    // let (_, s) = Integer::from_ber(s_bytes).unwrap();

    // Convert r and s bytes to BigInt (handling potential negative values for s)
    let r = BigInt::from_bytes_be(Sign::Plus, r_bytes);
    let s = BigInt::from_bytes_be(Sign::Plus, s_bytes);
    
    let r_temp = &r.to_signed_bytes_le();
    let s_temp = &s.to_signed_bytes_le();
    let r1 = asn1::BigInt::new(&r_temp).unwrap();
    let s1 = asn1::BigInt::new(&s_temp).unwrap();

    let result = asn1::write(|w| {
        w.write_element(&asn1::SequenceWriter::new(&|w| {
            w.write_element(&r1)?;
            w.write_element(&s1)?;
            Ok(())
        }))
    });

    // Encode the sequence to DER
    // let mut encoded = Vec::new();
    // sequence.encode(&mut encoded)?;

    Ok(result.unwrap())
    // Ok(encoded)
}

fn parse_rs(b: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, b)
}

fn parse_asn_bigint_rs(b: &[u8]) -> asn1::BigInt {
    asn1::BigInt::new(b).unwrap()

    // return asn1::BigInt::from(v.to_bytes_be().1.as_bytes()).unwrap()
    // BigInt::from_bytes_be(Sign::Plus, b)
}

fn parse_simple_asn1_bigint(b: &[u8]) -> simple_asn1::BigInt {
    simple_asn1::BigInt::from_bytes_be(Sign::Plus, b)

    // return asn1::BigInt::from(v.to_bytes_be().1.as_bytes()).unwrap()
    // BigInt::from_bytes_be(Sign::Plus, b)
}

fn parse_simple_asn1_rs_bigint(b: &[u8]) -> asn1_rs::BigInt {
    asn1_rs::BigInt::from_bytes_be(Sign::Plus, b)
}

impl Signer for MySigner {
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>, RusTLSError> {

        let session = self.pkcs11.session.lock().unwrap();

        let key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            // Attribute::
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
        println!("Input message ({:?}): {:?}", mechanism, String::from_utf8_lossy(&message));

        // rumqttc::tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256
        // let hash_digester = Hash::new();
        // rumqttc::tokio_rustls::rustls::crypto::hash::HashAlgorithm::SHA256


        // let hash = match session.digest(&mechanism, message) {
        // let version = sha256::digest(message);
        let hash = match session.digest(&Mechanism::Sha256, &message) {
            Ok(result) => result,
            Err(err) => {
                println!("Failed to create digest ({mechanism:?}): {err:?}");
                "".into()
            }
        };

        println!("hash (base64): {:?}", BASE64_URL_SAFE_NO_PAD.encode(&hash));
        // assert_eq!("rSM44KL7ndqH6sC574bsUjsi86onRHoW3z8ozPSHYRw", BASE64_URL_SAFE_NO_PAD.encode(&hash));

        println!("Digest output. len={:?}, hash={:x?}", hash.len(), hash);
        // let hash = session.digest(&mechanism, message).unwrap();

        
        // let signed_message = match session.sign(&mechanism, key, &hash) {
        let signature_raw = match session.sign(&mechanism, key, &hash) {
            Ok(result) => {
                println!("Signed data: (len={:?}) {:x?}", result.len(), &result);
                result
            },
            Err(err) => {
                println!("Failed to sign: {err:?}");
                "".into()
            },
        };

        // Split raw signature into r and s values (assuming 32 bytes each)
        let mut r_bytes = signature_raw[0..32].to_vec();
        let mut s_bytes = signature_raw[32..].to_vec();

        // let prefix = vec![0x00];
        // r_bytes.splice(0..0, prefix.iter().cloned());
        // s_bytes.splice(0..0, prefix.iter().cloned());

        // r_full_bytes.splice(1.., r_bytes.iter().cloned());

        // let mut s_full_bytes = vec![0x00];
        // s_full_bytes.splice(0..0, s_bytes.iter().cloned());

        // let sig_encoded = create_der_ecdsa_signature(&r_bytes, &s_bytes).unwrap();
        let sig_encoded = create_der_ecdsa_signature_using_bigint(&r_bytes, &s_bytes).unwrap();

        // assert_eq!(
        //     "MEQCIQCauL6ud7MxubZq6jOOWyJxI3EEaSTtb22wMGpCqJXkZgIfE0DCV5YaYD5kselE6XZyGyHcl8QpLJZv9Vts1yXfeg",
        //     BASE64_URL_SAFE_NO_PAD.encode(&sig_encoded),
        //     "Signature does not match",
        // );

        Ok(sig_encoded)

        // let r = BigInt::from(&r_bytes);
        // let s = BigInt::from_bytes_be(&s_bytes)?;

        // // Create a Sequence containing r and s
        // let sequence = asn1::Sequence::from(vec![r.into(), s.into()]);
        // // let sequence = Sequence::new(vec![r.into(), s.into()]);

        // // Encode the sequence to DER
        // let mut encoded = Vec::new();
        // sequence.(&mut encoded)?;

        // Ok(encoded)

        // Ok(Signature::new(|slice| {
        //     slice[..out_sig.len()].copy_from_slice(out_sig);
        //     out_sig.len()
        // }))
        // let sig2 = Signature::from_slice(&signed_message);

        

        // let sig = ecdsa::der::Signature::encode(&signed_message.as_slice());
        // let sig = signed_message.to_der_vec().unwrap();
        // println!("Signature data: (len={:?}) {:x?}", sig.len(), &sig);
        // Ok(sig)

        // Oksigned_message.to_der_vec_raw()
        // let der_encoded = signed_message.to_der_vec();
        // let der_encoded = match der_encoded {
        //     Ok(v) => {
        //         println!("DER encoded: len={:?} {:x?}", v.len(), v);
        //         v
        //     },
        //     Err(err) => {
        //         println!("DER encoding error. {err:?}");
        //         "".into()
        //     },
        // };
        // Ok(der_encoded)
        // ecdsa::SignatureEncoding

        // Ok(der_encoded)
        // let sig = ecdsa::Signature::from_slice(&signed_message);
        // Ok(sig.as_ref().into())
        // let v = Sequence::parse_data(&signed_message).unwrap();
        // println!("parsed data: {v:?}");
        // Ok(v)
        // let seq = signed_message.to_der_vec().unwrap();
        // Ok(seq)

        // let mut encoded_number = Vec::new();
        // encoded_number.write(&signed_message);
        // let result = asn1::write(|w| {
        //     w.write_element(&asn1::SequenceWriter::new(&|w| {
        //         w.write_element(&encoded_number)?;
        //         // w.write_element(&s)?;
        //         Ok(())
        //     }))
        // });

        // let encoder = der::Encoder;
        // encoder
        // let seq = asn1::write(signed_message).unwrap();
        
        // let seq = asn1::Sequence::parse(&signed_message).unwrap();
        // seq.
        // // TODO: Encode to ASN.1 DER format
        // let seq = asn1::write(|w| {
        //     w.write_element(&signed_message);
        //     w.
        // };
        
        // Ok(seq)
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
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            // RSA - Fail
            // SignatureScheme::RSA_PSS_SHA256,
            // SignatureScheme::RSA_PSS_SHA384,
            // SignatureScheme::RSA_PSS_SHA512,

            // SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

impl SigningKey for MySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        println!("Offered signature schemes. offered={:?}", offered);
        let supported = self.supported_schemes();
        for scheme in offered {
            if supported.contains(scheme) {
                println!("Matching scheme: {:?}", scheme.as_str());
                return Some(Box::new(MySigner { pkcs11: self.pkcs11.clone(), scheme: *scheme }));
            }
        }
        println!("Could not find a matching signing scheme. offered={:?}", offered);
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        // SignatureAlgorithm::RSA
        SignatureAlgorithm::ECDSA
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

    println!("Starting mqtt client: client_id={:?}, domain={:?}", mqtt_client_id, c8y_domain);
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

#[tokio::test]
async fn test_client_cert_signer() {

    // Message to sign: ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIGNsaWVudCBDZXJ0aWZpY2F0ZVZlcmlmeQB9DNs6ZTjv4f9ZhZey1JPUztq_LkyONGNk3CqebzDF6w==
    //
    // Message hash:
    // rSM44KL7ndqH6sC574bsUjsi86onRHoW3z8ozPSHYRw
    //
    // Signature encoded:
    // MEQCIQCauL6ud7MxubZq6jOOWyJxI3EEaSTtb22wMGpCqJXkZgIfE0DCV5YaYD5kselE6XZyGyHcl8QpLJZv9Vts1yXfeg

    let pkcs11module = std::env::var("PKCS11_MODULE");
    let pkcs11module = pkcs11module.as_deref().unwrap_or("/opt/homebrew/lib/pkcs11/opensc-pkcs11.so");
    let pkcs11client = Pkcs11::new(pkcs11module).unwrap();
    pkcs11client.initialize(CInitializeArgs::OsThreads).unwrap();

    let slot = pkcs11client.get_slots_with_token().unwrap().remove(0);
    let session = pkcs11client.open_ro_session(slot).unwrap();
    session.login(UserType::User, Some(&AuthPin::new("123456".into()))).unwrap();

    let pkcs11 = PKCS11 { session: Arc::new(Mutex::new(session)) };
    // let chain = get_certificate_der(pkcs11.clone()).unwrap();
    let my_signing_key = Arc::new(MySigningKey { pkcs11 });
    
    let signer = my_signing_key.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256]).unwrap();
    let message = BASE64_URL_SAFE.decode("ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIGNsaWVudCBDZXJ0aWZpY2F0ZVZlcmlmeQB9DNs6ZTjv4f9ZhZey1JPUztq_LkyONGNk3CqebzDF6w==").unwrap();
    let sig = signer.sign(&message).unwrap();

    assert_eq!("rSM44KL7ndqH6sC574bsUjsi86onRHoW3z8ozPSHYRw", BASE64_URL_SAFE.encode(sig));
    
    let _ = sig;

}


#[tokio::test]
async fn test_sig_decoder() {
    let signature_raw: [u8; 64] = [12, 134, 45, 206, 14, 82, 48, 131, 85, 107, 153, 242, 215, 171, 6, 95, 142, 115, 115, 163, 233, 43, 57, 20, 244, 20, 185, 217, 57, 50, 121, 119, 127, 224, 225, 70, 120, 77, 108, 126, 30, 76, 174, 27, 162, 233, 163, 127, 20, 79, 215, 131, 117, 135, 240, 208, 52, 54, 215, 168, 170, 142, 67, 150];
    // let signature_raw = BASE64_URL_SAFE.decode("ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIGNsaWVudCBDZXJ0aWZpY2F0ZVZlcmlmeQB9DNs6ZTjv4f9ZhZey1JPUztq_LkyONGNk3CqebzDF6w==").unwrap();

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let r = parse_rs(&r_bytes);
    let s = parse_rs(&s_bytes);

    assert_eq!("5664827823522302053252121256142066174752445323573986797468973731770988132727", r.to_string());
    assert_eq!("57841060305378809294557622035767714131062944761800257564159872864525742916502", s.to_string());
}

#[tokio::test]
async fn test_parse_asn_bigint() {
    let signature_raw: [u8; 64] = [12, 134, 45, 206, 14, 82, 48, 131, 85, 107, 153, 242, 215, 171, 6, 95, 142, 115, 115, 163, 233, 43, 57, 20, 244, 20, 185, 217, 57, 50, 121, 119, 127, 224, 225, 70, 120, 77, 108, 126, 30, 76, 174, 27, 162, 233, 163, 127, 20, 79, 215, 131, 117, 135, 240, 208, 52, 54, 215, 168, 170, 142, 67, 150];
    // let signature_raw = BASE64_URL_SAFE.decode("ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIGNsaWVudCBDZXJ0aWZpY2F0ZVZlcmlmeQB9DNs6ZTjv4f9ZhZey1JPUztq_LkyONGNk3CqebzDF6w==").unwrap();

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let r = parse_asn_bigint_rs(&r_bytes);
    let s = parse_asn_bigint_rs(&s_bytes);

    assert_eq!(b"5664827823522302053252121256142066174752445323573986797468973731770988132727", r.as_bytes());
    assert_eq!(b"57841060305378809294557622035767714131062944761800257564159872864525742916502", s.as_bytes());
}

#[tokio::test]
async fn test_parse_simple_asn1_bigint() {
    let signature_raw: [u8; 64] = [12, 134, 45, 206, 14, 82, 48, 131, 85, 107, 153, 242, 215, 171, 6, 95, 142, 115, 115, 163, 233, 43, 57, 20, 244, 20, 185, 217, 57, 50, 121, 119, 127, 224, 225, 70, 120, 77, 108, 126, 30, 76, 174, 27, 162, 233, 163, 127, 20, 79, 215, 131, 117, 135, 240, 208, 52, 54, 215, 168, 170, 142, 67, 150];
    // let signature_raw = BASE64_URL_SAFE.decode("ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIGNsaWVudCBDZXJ0aWZpY2F0ZVZlcmlmeQB9DNs6ZTjv4f9ZhZey1JPUztq_LkyONGNk3CqebzDF6w==").unwrap();

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let r = parse_simple_asn1_bigint(&r_bytes);
    let s = parse_simple_asn1_bigint(&s_bytes);

    assert_eq!("5664827823522302053252121256142066174752445323573986797468973731770988132727", r.to_string());
    assert_eq!("57841060305378809294557622035767714131062944761800257564159872864525742916502", s.to_string());
}

#[tokio::test]
async fn test_parse_simple_asn1_rs_bigint() {
    let signature_raw: [u8; 64] = [12, 134, 45, 206, 14, 82, 48, 131, 85, 107, 153, 242, 215, 171, 6, 95, 142, 115, 115, 163, 233, 43, 57, 20, 244, 20, 185, 217, 57, 50, 121, 119, 127, 224, 225, 70, 120, 77, 108, 126, 30, 76, 174, 27, 162, 233, 163, 127, 20, 79, 215, 131, 117, 135, 240, 208, 52, 54, 215, 168, 170, 142, 67, 150];
    // let signature_raw = BASE64_URL_SAFE.decode("ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIGNsaWVudCBDZXJ0aWZpY2F0ZVZlcmlmeQB9DNs6ZTjv4f9ZhZey1JPUztq_LkyONGNk3CqebzDF6w==").unwrap();

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let r = parse_simple_asn1_rs_bigint(&r_bytes);
    let s = parse_simple_asn1_rs_bigint(&s_bytes);

    assert_eq!("5664827823522302053252121256142066174752445323573986797468973731770988132727", r.to_string());
    assert_eq!("57841060305378809294557622035767714131062944761800257564159872864525742916502", s.to_string());
}

#[tokio::test]
async fn test_parse_interger_as_bigint() {
    let signature_raw: [u8; 64] = [12, 134, 45, 206, 14, 82, 48, 131, 85, 107, 153, 242, 215, 171, 6, 95, 142, 115, 115, 163, 233, 43, 57, 20, 244, 20, 185, 217, 57, 50, 121, 119, 127, 224, 225, 70, 120, 77, 108, 126, 30, 76, 174, 27, 162, 233, 163, 127, 20, 79, 215, 131, 117, 135, 240, 208, 52, 54, 215, 168, 170, 142, 67, 150];
    // let signature_raw = BASE64_URL_SAFE.decode("ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIGNsaWVudCBDZXJ0aWZpY2F0ZVZlcmlmeQB9DNs6ZTjv4f9ZhZey1JPUztq_LkyONGNk3CqebzDF6w==").unwrap();

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let r = asn1_rs::Integer::new(&r_bytes);
    let s = asn1_rs::Integer::new(&s_bytes);

    let r = r.as_bigint();
    let s = s.as_bigint();

    assert_eq!("5664827823522302053252121256142066174752445323573986797468973731770988132727", r.to_string());
    assert_eq!("57841060305378809294557622035767714131062944761800257564159872864525742916502", s.to_string());
}

/// X.509 `AlgorithmIdentifier`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)] // NOTE: added `Sequence`
// #[derive(Sequence)]
pub struct AlgorithmIdentifier<'a> {
    /// This field contains an ASN.1 `OBJECT IDENTIFIER`, a.k.a. OID.
    pub algorithm: ObjectIdentifier,

    /// This field is `OPTIONAL` and contains the ASN.1 `ANY` type, which
    /// in this example allows arbitrary algorithm-defined parameters.
    pub parameters: Option<AnyRef<'a>>
}

// impl<'a> der::DecodeValue<'a> for AlgorithmIdentifier<'a> {
//     fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
//        // The `der::Decoder::Decode` method can be used to decode any
//        // type which impls the `Decode` trait, which is impl'd for
//        // all of the ASN.1 built-in types in the `der` crate.
//        //
//        // Note that if your struct's fields don't contain an ASN.1
//        // built-in type specifically, there are also helper methods
//        // for all of the built-in types supported by this library
//        // which can be used to select a specific type.
//        //
//        // For example, another way of decoding this particular field,
//        // which contains an ASN.1 `OBJECT IDENTIFIER`, is by calling
//        // `decoder.oid()`. Similar methods are defined for other
//        // ASN.1 built-in types.
//        let algorithm = reader.decode()?;

//        // This field contains an ASN.1 `OPTIONAL` type. The `der` crate
//        // maps this directly to Rust's `Option` type and provides
//        // impls of the `Decode` and `Encode` traits for `Option`.
//        // To explicitly request an `OPTIONAL` type be decoded, use the
//        // `decoder.optional()` method.
//        let parameters = reader.decode()?;

//        // The value returned from the provided `FnOnce` will be
//        // returned from the `any.sequence(...)` call above.
//        // Note that the entire sequence body *MUST* be consumed
//        // or an error will be returned.
//        Ok(Self { algorithm, parameters })
//     }
// }



// #[tokio::test]
#[test]
fn test_decode_asn1_der() {
    let sig_raw = BASE64_URL_SAFE_NO_PAD.decode("MEQCIQCauL6ud7MxubZq6jOOWyJxI3EEaSTtb22wMGpCqJXkZgIfE0DCV5YaYD5kselE6XZyGyHcl8QpLJZv9Vts1yXfeg").unwrap();

    let seq = asn1_rs::Sequence::from_ber(&sig_raw).expect("serialization error");
    // seq.1.der_iter().map(|d| => Ok(d).)
    let r = asn1_rs::Integer::from_ber(&sig_raw).expect("serialization error");
    // let s = asn1_rs::Integer::from_ber(s_bytes).expect("serialization error");
    
    let decoded_algorithm_identifier = AlgorithmIdentifier::from_der(
        &sig_raw
    ).unwrap();

    println!("Parameters: {:?}", decoded_algorithm_identifier.parameters);
    

    // let sig_decoded = der_decode(&signature_raw);

    let _ = decoded_algorithm_identifier;
}

#[test]
fn test_signature_encoding_case1() {
    // case 1: golang has prefixed 0x00 values in the r and s values, length is 33 bytes (not 32!)
    let signature_raw: [u8; 64] = [142, 102, 8, 28, 159, 10, 211, 68, 100, 17, 39, 6, 113, 189, 132, 21, 20, 139, 55, 179, 45, 35, 209, 13, 187, 34, 44, 216, 5, 95, 43, 108, 129, 152, 120, 162, 93, 233, 183, 149, 115, 106, 113, 154, 89, 13, 62, 42, 168, 3, 193, 181, 31, 59, 41, 199, 153, 64, 167, 39, 2, 65, 80, 77];
    let golang_output = String::from("MEYCIQCOZggcnwrTRGQRJwZxvYQVFIs3sy0j0Q27IizYBV8rbAIhAIGYeKJd6beVc2pxmlkNPiqoA8G1Hzspx5lApycCQVBN");

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let sig_encoded = create_der_ecdsa_signature_using_bigint(&r_bytes, &s_bytes).unwrap();
    let rust_output = BASE64_STANDARD_NO_PAD.encode(sig_encoded);
    
    assert_eq!(rust_output, golang_output);
}

#[test]
fn test_signature_encoding_case2() {
    // case 2: golang does not have prefixed 0x00 values in r and s values, length is 32 bytes
    let signature_raw: [u8; 64] = [76, 98, 169, 50, 155, 237, 19, 2, 47, 194, 117, 54, 102, 66, 2, 7, 143, 173, 96, 161, 32, 84, 100, 160, 15, 135, 115, 87, 127, 250, 0, 82, 18, 193, 222, 211, 47, 153, 133, 123, 138, 79, 154, 174, 232, 51, 124, 50, 183, 166, 82, 231, 7, 65, 204, 200, 102, 130, 99, 62, 58, 75, 85, 87];
    let golang_output = String::from("MEQCIExiqTKb7RMCL8J1NmZCAgePrWChIFRkoA+Hc1d/+gBSAiASwd7TL5mFe4pPmq7oM3wyt6ZS5wdBzMhmgmM+OktVVw");

    let r_bytes = signature_raw[0..32].to_vec();
    let s_bytes = signature_raw[32..].to_vec();

    let sig_encoded = create_der_ecdsa_signature_using_bigint(&r_bytes, &s_bytes).unwrap();
    let rust_output = BASE64_STANDARD_NO_PAD.encode(sig_encoded);

    assert_eq!(rust_output, golang_output);
}

