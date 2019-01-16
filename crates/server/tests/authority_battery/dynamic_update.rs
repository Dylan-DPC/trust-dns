use std::net::Ipv4Addr;
use std::str::FromStr;

use trust_dns::op::update_message;
use trust_dns::op::{Message, Query, ResponseCode};
use trust_dns::proto::rr::dnssec::rdata::{DNSSECRecordType, DNSKEY};
use trust_dns::proto::rr::{Name, RData, Record, RecordSet, RecordType};
use trust_dns::rr::dnssec::{Algorithm, Signer, SupportedAlgorithms, Verifier};
use trust_dns::serialize::binary::{BinDecodable, BinEncodable};
use trust_dns_server::authority::{Authority, MessageRequest};

pub fn test_create<A: Authority>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("create.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);
        let record = Record::from_rdata(
            name.clone(),
            8,
            RecordType::A,
            RData::A(Ipv4Addr::new(127, 0, 0, 10)),
        );
        let mut message =
            update_message::create(record.into(), Name::from_str("example.com.").unwrap());
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

        // trying to create again should error
        assert_eq!(
            authority.update(&request).unwrap_err(),
            ResponseCode::YXRRSet
        );
    }
}

fn test_create_multi<A: Authority>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("create-multi.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);
        // create a record
        let mut record = Record::with(name.clone(), RecordType::A, 8);
        record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
        let record = record;

        let mut record2 = record.clone();
        record2.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 11)));
        let record2 = record2;

        let mut rrset = RecordSet::from(record.clone());
        rrset.insert(record2.clone(), 0);
        let rrset = rrset;

        let mut message =
            update_message::create(rrset.into(), Name::from_str("example.com.").unwrap());
        message.finalize(key, 1).expect("failed to sign message");

        let message = message.to_bytes().unwrap();
        let request = MessageRequest::from_bytes(&message).unwrap();

        assert!(authority.update(&request).expect("create failed"));

        let query = Query::query(name, RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));

        // trying to create again should error
        assert_eq!(
            authority.update(&request).unwrap_err(),
            ResponseCode::YXRRSet
        );
    }
}

// #[cfg(feature = "dnssec")]
// #[test]
// fn test_append() {
//     let mut io_loop = Runtime::new().unwrap();
//     let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

//     // append a record
//     let mut record = Record::with(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );
//     record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
//     let record = record;

//     // first check the must_exist option
//     io_loop.spawn(bg);
//     let result = io_loop
//         .block_on(client.append(record.clone(), origin.clone(), true))
//         .expect("append failed");
//     assert_eq!(result.response_code(), ResponseCode::NXRRSet);

//     // next append to a non-existent RRset
//     let result = io_loop
//         .block_on(client.append(record.clone(), origin.clone(), false))
//         .expect("append failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // verify record contents
//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 1);
//     assert_eq!(result.answers()[0], record);

//     // will fail if already set and not the same value.
//     let mut record2 = record.clone();
//     record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
//     let record2 = record2;

//     let result = io_loop
//         .block_on(client.append(record2.clone(), origin.clone(), true))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 2);

//     assert!(result.answers().iter().any(|rr| *rr == record));
//     assert!(result.answers().iter().any(|rr| *rr == record2));

//     // show that appending the same thing again is ok, but doesn't add any records
//     let result = io_loop
//         .block_on(client.append(record.clone(), origin.clone(), true))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 2);
// }

// #[cfg(feature = "dnssec")]
// #[test]
// fn test_append_multi() {
//     let mut io_loop = Runtime::new().unwrap();
//     let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

//     // append a record
//     let mut record = Record::with(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );
//     record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

//     // first check the must_exist option
//     io_loop.spawn(bg);
//     let result = io_loop
//         .block_on(client.append(record.clone(), origin.clone(), true))
//         .expect("append failed");
//     assert_eq!(result.response_code(), ResponseCode::NXRRSet);

//     // next append to a non-existent RRset
//     let result = io_loop
//         .block_on(client.append(record.clone(), origin.clone(), false))
//         .expect("append failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // verify record contents
//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 1);
//     assert_eq!(result.answers()[0], record);

//     // will fail if already set and not the same value.
//     let mut record2 = record.clone();
//     record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
//     let mut record3 = record.clone();
//     record3.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 12)));

//     // build the append set
//     let mut rrset = record2.clone().into_record_set();
//     rrset.insert(record3.clone(), 0);

//     let result = io_loop
//         .block_on(client.append(rrset, origin.clone(), true))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 3);

//     assert!(result.answers().iter().any(|rr| *rr == record));
//     assert!(result.answers().iter().any(|rr| *rr == record2));
//     assert!(result.answers().iter().any(|rr| *rr == record3));

//     // show that appending the same thing again is ok, but doesn't add any records
//     // TODO: technically this is a test for the Server, not client...
//     let result = io_loop
//         .block_on(client.append(record.clone(), origin.clone(), true))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 3);
// }

// #[cfg(feature = "dnssec")]
// #[test]
// fn test_compare_and_swap() {
//     let mut io_loop = Runtime::new().unwrap();
//     let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

//     // create a record
//     let mut record = Record::with(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );
//     record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
//     let record = record;

//     io_loop.spawn(bg);
//     let result = io_loop
//         .block_on(client.create(record.clone(), origin.clone()))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let current = record;
//     let mut new = current.clone();
//     new.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
//     let new = new;

//     let result = io_loop
//         .block_on(client.compare_and_swap(current.clone(), new.clone(), origin.clone()))
//         .expect("compare_and_swap failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(new.name().clone(), new.dns_class(), new.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 1);
//     assert!(result.answers().iter().any(|rr| *rr == new));
//     assert!(!result.answers().iter().any(|rr| *rr == current));

//     // check the it fails if tried again.
//     let mut not = new.clone();
//     not.set_rdata(RData::A(Ipv4Addr::new(102, 12, 102, 12)));
//     let not = not;

//     let result = io_loop
//         .block_on(client.compare_and_swap(current, not.clone(), origin.clone()))
//         .expect("compare_and_swap failed");
//     assert_eq!(result.response_code(), ResponseCode::NXRRSet);

//     let result = io_loop
//         .block_on(client.query(new.name().clone(), new.dns_class(), new.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 1);
//     assert!(result.answers().iter().any(|rr| *rr == new));
//     assert!(!result.answers().iter().any(|rr| *rr == not));
// }

// #[cfg(feature = "dnssec")]
// #[test]
// fn test_compare_and_swap_multi() {
//     let mut io_loop = Runtime::new().unwrap();
//     let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

//     // create a record
//     let mut current = RecordSet::with_ttl(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );

//     let current1 = current
//         .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 10)))
//         .clone();
//     let current2 = current
//         .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 11)))
//         .clone();
//     let current = current;

//     io_loop.spawn(bg);
//     let result = io_loop
//         .block_on(client.create(current.clone(), origin.clone()))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let mut new = RecordSet::with_ttl(current.name().clone(), current.record_type(), current.ttl());
//     let new1 = new
//         .new_record(&RData::A(Ipv4Addr::new(100, 10, 101, 10)))
//         .clone();
//     let new2 = new
//         .new_record(&RData::A(Ipv4Addr::new(100, 10, 101, 11)))
//         .clone();
//     let new = new;

//     let result = io_loop
//         .block_on(client.compare_and_swap(current.clone(), new.clone(), origin.clone()))
//         .expect("compare_and_swap failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 2);
//     assert!(result.answers().iter().any(|rr| *rr == new1));
//     assert!(result.answers().iter().any(|rr| *rr == new2));
//     assert!(!result.answers().iter().any(|rr| *rr == current1));
//     assert!(!result.answers().iter().any(|rr| *rr == current2));

//     // check the it fails if tried again.
//     let mut not = new1.clone();
//     not.set_rdata(RData::A(Ipv4Addr::new(102, 12, 102, 12)));
//     let not = not;

//     let result = io_loop
//         .block_on(client.compare_and_swap(current, not.clone(), origin.clone()))
//         .expect("compare_and_swap failed");
//     assert_eq!(result.response_code(), ResponseCode::NXRRSet);

//     let result = io_loop
//         .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 2);
//     assert!(result.answers().iter().any(|rr| *rr == new1));
//     assert!(!result.answers().iter().any(|rr| *rr == not));
// }

// #[cfg(feature = "dnssec")]
// #[test]
// fn test_delete_by_rdata() {
//     let mut io_loop = Runtime::new().unwrap();
//     let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

//     // append a record
//     let mut record1 = Record::with(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );
//     record1.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

//     // first check the must_exist option
//     io_loop.spawn(bg);
//     let result = io_loop
//         .block_on(client.delete_by_rdata(record1.clone(), origin.clone()))
//         .expect("delete failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // next create to a non-existent RRset
//     let result = io_loop
//         .block_on(client.create(record1.clone(), origin.clone()))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let mut record2 = record1.clone();
//     record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
//     let result = io_loop
//         .block_on(client.append(record2.clone(), origin.clone(), true))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // verify record contents
//     let result = io_loop
//         .block_on(client.delete_by_rdata(record2.clone(), origin.clone()))
//         .expect("delete failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(
//             record1.name().clone(),
//             record1.dns_class(),
//             record1.rr_type(),
//         )).expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 1);
//     assert!(result.answers().iter().any(|rr| *rr == record1));
// }

// #[cfg(feature = "dnssec")]
// #[test]
// fn test_delete_by_rdata_multi() {
//     let mut io_loop = Runtime::new().unwrap();
//     let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

//     // append a record
//     let mut rrset = RecordSet::with_ttl(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );

//     let record1 = rrset
//         .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 10)))
//         .clone();
//     let record2 = rrset
//         .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 11)))
//         .clone();
//     let record3 = rrset
//         .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 12)))
//         .clone();
//     let record4 = rrset
//         .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 13)))
//         .clone();
//     let rrset = rrset;

//     // first check the must_exist option
//     io_loop.spawn(bg);
//     let result = io_loop
//         .block_on(client.delete_by_rdata(rrset.clone(), origin.clone()))
//         .expect("delete failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // next create to a non-existent RRset
//     let result = io_loop
//         .block_on(client.create(rrset.clone(), origin.clone()))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // append a record
//     let mut rrset = RecordSet::with_ttl(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );

//     let record1 = rrset.new_record(record1.rdata()).clone();
//     let record3 = rrset.new_record(record3.rdata()).clone();
//     let rrset = rrset;

//     let result = io_loop
//         .block_on(client.append(rrset.clone(), origin.clone(), true))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // verify record contents
//     let result = io_loop
//         .block_on(client.delete_by_rdata(rrset.clone(), origin.clone()))
//         .expect("delete failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(
//             record1.name().clone(),
//             record1.dns_class(),
//             record1.rr_type(),
//         )).expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);
//     assert_eq!(result.answers().len(), 2);
//     assert!(!result.answers().iter().any(|rr| *rr == record1));
//     assert!(result.answers().iter().any(|rr| *rr == record2));
//     assert!(!result.answers().iter().any(|rr| *rr == record3));
//     assert!(result.answers().iter().any(|rr| *rr == record4));
// }

// #[cfg(feature = "dnssec")]
// #[test]
// fn test_delete_rrset() {
//     let mut io_loop = Runtime::new().unwrap();
//     let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

//     // append a record
//     let mut record = Record::with(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );
//     record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

//     // first check the must_exist option
//     io_loop.spawn(bg);
//     let result = io_loop
//         .block_on(client.delete_rrset(record.clone(), origin.clone()))
//         .expect("delete failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // next create to a non-existent RRset
//     let result = io_loop
//         .block_on(client.create(record.clone(), origin.clone()))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let mut record = record.clone();
//     record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
//     let result = io_loop
//         .block_on(client.append(record.clone(), origin.clone(), true))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // verify record contents
//     let result = io_loop
//         .block_on(client.delete_rrset(record.clone(), origin.clone()))
//         .expect("delete failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NXDomain);
//     assert_eq!(result.answers().len(), 0);
// }

// #[cfg(feature = "dnssec")]
// #[test]
// fn test_delete_all() {
//     let mut io_loop = Runtime::new().unwrap();
//     let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

//     // append a record
//     let mut record = Record::with(
//         Name::from_str("new.example.com").unwrap(),
//         RecordType::A,
//         Duration::minutes(5).num_seconds() as u32,
//     );
//     record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

//     // first check the must_exist option
//     io_loop.spawn(bg);
//     let result = io_loop
//         .block_on(client.delete_all(record.name().clone(), origin.clone(), DNSClass::IN))
//         .expect("delete failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // next create to a non-existent RRset
//     let result = io_loop
//         .block_on(client.create(record.clone(), origin.clone()))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let mut record = record.clone();
//     record.set_rr_type(RecordType::AAAA);
//     record.set_rdata(RData::AAAA(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)));
//     let result = io_loop
//         .block_on(client.create(record.clone(), origin.clone()))
//         .expect("create failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     // verify record contents
//     let result = io_loop
//         .block_on(client.delete_all(record.name().clone(), origin.clone(), DNSClass::IN))
//         .expect("delete failed");
//     assert_eq!(result.response_code(), ResponseCode::NoError);

//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), RecordType::A))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NXDomain);
//     assert_eq!(result.answers().len(), 0);

//     let result = io_loop
//         .block_on(client.query(record.name().clone(), record.dns_class(), RecordType::AAAA))
//         .expect("query failed");
//     assert_eq!(result.response_code(), ResponseCode::NXDomain);
//     assert_eq!(result.answers().len(), 0);
// }

pub fn add_auth<A: Authority>(authority: &mut A) -> Vec<Signer> {
    use trust_dns::rr::rdata::key::KeyUsage;
    use trust_dns_server::config::dnssec::*;

    let update_name = Name::from_str("update")
        .unwrap()
        .append_domain(&authority.origin().to_owned().into());

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

        let signer = key_config
            .try_into_signer(update_name.clone())
            .expect("failed to read key_config");
        let public_key = signer
            .key()
            .to_sig0key_with_usage(Algorithm::RSASHA512, KeyUsage::Host)
            .expect("failed to get sig0 key");

        authority
            .add_update_auth_key(update_name.clone(), public_key)
            .expect("failed to add signer to zone");
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

        let signer = key_config
            .try_into_signer(update_name.clone())
            .expect("failed to read key_config");
        let public_key = signer
            .key()
            .to_sig0key_with_usage(Algorithm::ED25519, KeyUsage::Host)
            .expect("failed to get sig0 key");

        authority
            .add_update_auth_key(update_name, public_key)
            .expect("failed to add signer to zone");
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
                    test_create,
                );
            }
        }
    };
}
