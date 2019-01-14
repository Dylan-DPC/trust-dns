use std::net::Ipv4Addr;
use std::str::FromStr;

use trust_dns::op::{Message, Query};
use trust_dns::op::update_message;
use trust_dns::rr::dnssec::{Algorithm, SupportedAlgorithms, Verifier, Signer};
use trust_dns::proto::rr::dnssec::rdata::{DNSSECRecordType, DNSKEY};
use trust_dns::proto::rr::{Name, RData, Record, RecordType};
use trust_dns_server::authority::{Authority, MessageRequest};
use trust_dns::serialize::binary::{BinEncodable, BinDecodable};

pub fn test_insert_record<A: Authority>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("insert.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str()).unwrap().append_name(&name);
        let record = Record::from_rdata(
            name.clone(), 
            8,
            RecordType::A, 
            RData::A(Ipv4Addr::new(127, 0, 0, 10))
        );
        let tbs_message = update_message::create(record.into(), Name::from_str("example.com.").unwrap());
    
        let mut message = tbs_message.clone();
        message.finalize(key, 1).expect("failed to sign message");
        let message = message.to_bytes().unwrap();
        let request = MessageRequest::from_bytes(&message).unwrap();

        assert!(authority.update(&request).expect("create failed"));

        let query = Query::query(name, RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        match lookup
            .into_iter()
            .next()
            .expect("A record not found in authity")
            .rdata()
        {
            RData::A(ip) => assert_eq!(Ipv4Addr::new(127, 0, 0, 10), *ip),
            _ => panic!("wrong rdata type returned"),
        }
    }
}

pub fn add_auth<A: Authority>(authority: &mut A) -> Vec<Signer> {
    use trust_dns_server::config::dnssec::*;
    use trust_dns::rr::rdata::key::KeyUsage;

    let update_name = Name::from_str("update").unwrap().append_domain(&authority.origin().to_owned().into());

    let mut keys = Vec::<Signer>::new();

    // TODO: support RSA signing with ring
    // rsa
    #[cfg(feature = "dnssec-openssl")]
    {
        let key_config = KeyConfig {
            key_path: "tests/named_test_configs/dnssec/rsa_2048.pem".to_string(),
            password: Some("123456".to_string()),
            algorithm: Algorithm::RSASHA512.to_string(),
            signer_name: Some(update_name.clone().to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config.try_into_signer(update_name.clone()).expect("failed to read key_config");
        let public_key = signer.key().to_sig0key_with_usage(Algorithm::RSASHA512, KeyUsage::Host).expect("failed to get sig0 key");

        authority.add_update_auth_key(update_name.clone(), public_key).expect("failed to add signer to zone");
        keys.push(signer);
    }

    // // TODO: why are ecdsa tests failing in this context?
    // // ecdsa_p256
    // {
    //     let key_config = KeyConfig {
    //         key_path: "tests/named_test_configs/dnssec/ecdsa_p256.pem".to_string(),
    //         password: None,
    //         algorithm: Algorithm::ECDSAP256SHA256.to_string(),
    //         signer_name: Some(signer_name.clone().to_string()),
    //         is_zone_signing_key: Some(true),
    //         is_zone_update_auth: Some(false),
    //     };

    //     let signer = key_config.try_into_signer(signer_name.clone()).expect("failed to read key_config");
    //     keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
    //     authority.add_zone_signing_key(signer).expect("failed to add signer to zone");
    //     authority.secure_zone().expect("failed to sign zone");
    // }

    // // ecdsa_p384
    // {
    //     let key_config = KeyConfig {
    //         key_path: "tests/named_test_configs/dnssec/ecdsa_p384.pem".to_string(),
    //         password: None,
    //         algorithm: Algorithm::ECDSAP384SHA384.to_string(),
    //         signer_name: Some(signer_name.clone().to_string()),
    //         is_zone_signing_key: Some(true),
    //         is_zone_update_auth: Some(false),
    //     };

    //     let signer = key_config.try_into_signer(signer_name.clone()).expect("failed to read key_config");
    //     keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
    //     authority.add_zone_signing_key(signer).expect("failed to add signer to zone");
    //     authority.secure_zone().expect("failed to sign zone");
    // }

    // ed 25519
    #[cfg(feature = "dnssec-ring")]
    {
        let key_config = KeyConfig {
            key_path: "tests/named_test_configs/dnssec/ed25519.pk8".to_string(),
            password: None,
            algorithm: Algorithm::ED25519.to_string(),
            signer_name: Some(update_name.clone().to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config.try_into_signer(update_name.clone()).expect("failed to read key_config");
        let public_key = signer.key().to_sig0key_with_usage(Algorithm::ED25519, KeyUsage::Host).expect("failed to get sig0 key");

        authority.add_update_auth_key(update_name, public_key).expect("failed to add signer to zone");
        keys.push(signer);
    }

    keys
}

macro_rules! define_update_test {
    ($new:ident; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                let mut authority = ::$new("tests/named_test_configs/example.com.zone", module_path!(), stringify!($f));
                let keys = ::authority_battery::dynamic_update::add_auth(&mut authority);
                ::authority_battery::dynamic_update::$f(authority, &keys);
            }
        )*
    }
}

macro_rules! dynamic_update {
    ($new:ident) => {
        #[cfg(test)]
        mod dynamic_update {
            mod $new {
                define_update_test!($new;
                    test_insert_record,
                );
            }
        }
    };
}
