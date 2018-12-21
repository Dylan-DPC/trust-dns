use std::net::Ipv4Addr;
use std::str::FromStr;

use trust_dns::op::{Message, Query};
use trust_dns::rr::dnssec::SupportedAlgorithms;
use trust_dns::rr::{Name, RData, RecordType};
use trust_dns_server::authority::{Authority, MessageRequest};

pub fn test_a_lookup<A: Authority>(authority: A) {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

    match lookup
        .into_iter()
        .next()
        .expect("A record not found in authity")
        .rdata()
    {
        RData::A(ip) => assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *ip),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_soa<A: Authority>(authority: A) {
    let lookup = authority.soa();

    match lookup
        .into_iter()
        .next()
        .expect("SOA record not found in authity")
        .rdata()
    {
        RData::SOA(soa) => {
            assert_eq!(Name::from_str("trust-dns.org.").unwrap(), *soa.mname());
            assert_eq!(Name::from_str("root.trust-dns.org.").unwrap(), *soa.rname());
            assert_eq!(199609203, soa.serial());
            assert_eq!(28800, soa.refresh());
            assert_eq!(7200, soa.retry());
            assert_eq!(604800, soa.expire());
            assert_eq!(86400, soa.minimum());
        }
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_ns<A: Authority>(authority: A) {
    let lookup = authority.ns(false, SupportedAlgorithms::new());

    match lookup
        .into_iter()
        .next()
        .expect("NS record not found in authity")
        .rdata()
    {
        RData::NS(name) => assert_eq!(Name::from_str("trust-dns.org.").unwrap(), *name),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_update_errors<A: Authority>(mut authority: A) {
    use trust_dns::serialize::binary::BinDecodable;

    let message = Message::default();
    let bytes = message.to_vec().unwrap();
    let update = MessageRequest::from_bytes(&bytes).unwrap();

    // this is expected to fail, i.e. updates are not allowed
    assert!(authority.update(&update).is_err());
}

pub fn add_auth<A: Authority>(authority: &mut A) -> Vec<DNSKEY> {
    use trust_dns_server::config::dnssec::*;
    let signer_name = Name::from(authority.origin().to_owned());

    let mut keys = Vec::<DNSKEY>::new();

    // TODO: support RSA signing with ring
    #[cfg(feature = "dnssec-openssl")]
    // rsa
    {
        let key_config = KeyConfig {
            key_path: "tests/named_test_configs/dnssec/rsa_2048.pem".to_string(),
            password: Some("123456".to_string()),
            algorithm: Algorithm::RSASHA512.to_string(),
            signer_name: Some(signer_name.clone().to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config.try_into_signer(signer_name.clone()).expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        authority.add_secure_key(signer).expect("failed to add signer to zone");
        authority.secure_zone().expect("failed to sign zone");
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
    //     authority.add_secure_key(signer).expect("failed to add signer to zone");
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
    //     authority.add_secure_key(signer).expect("failed to add signer to zone");
    //     authority.secure_zone().expect("failed to sign zone");
    // }

    // ed 25519
    #[cfg(feature = "dnssec-ring")]
    {
        let key_config = KeyConfig {
            key_path: "tests/named_test_configs/dnssec/ed25519.pk8".to_string(),
            password: None,
            algorithm: Algorithm::ED25519.to_string(),
            signer_name: Some(signer_name.clone().to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config.try_into_signer(signer_name.clone()).expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        authority.add_secure_key(signer).expect("failed to add signer to zone");
        authority.secure_zone().expect("failed to sign zone");
    }

    keys
}


macro_rules! define_update_test {
    ($new:ident; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                let authority = ::$new("tests/named_test_configs/example.com.zone", module_path!(), stringify!($f));
                ::authority_battery::basic::$f(authority);
            }
        )*
    }
}

macro_rules! dynamic_update {
    ($new:ident) => {
        #[cfg(test)]
        mod dynami_update {
            mod $new {
                define_update_test!($new;
                    test_a_lookup,
                    test_soa,
                    test_ns,
                    test_update_errors,
                );
            }
        }
    };
}
