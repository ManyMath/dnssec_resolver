use crate::engine::{Exchange, NoNetworkRuntime, Transport};
#[path = "../tests/support/mod.rs"]
pub(crate) mod support;
use futures_util::StreamExt;
use hickory_net::{
    proto::{
        dnssec::{Algorithm, DigestType, PublicKeyBuf, TrustAnchors, rdata::DNSKEY},
        op::{DnsRequest, DnsRequestOptions, Message, Query, ResponseCode},
        rr::{Name, RData, Record, RecordType, rdata::TXT},
    },
    runtime::RuntimeProvider,
    xfer::DnsHandle,
};
use std::sync::{Arc, atomic::AtomicUsize};
use tokio::sync::mpsc;

fn transport() -> (Transport, mpsc::Receiver<Exchange>) {
    let (requests, receiver) = mpsc::channel(16);
    let transport = Transport {
        requests,
        count: Arc::new(AtomicUsize::new(0)),
        max_queries: 8,
        pending: Arc::default(),
    };
    (transport, receiver)
}

fn request(id: u16, name: &str, kind: RecordType) -> DnsRequest {
    let mut message = Message::query();
    message.metadata.id = id;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    DnsRequest::new(message, DnsRequestOptions::default())
}

fn txt(name: &str) -> Record {
    Record::from_rdata(
        Name::from_ascii(name).unwrap(),
        300,
        RData::TXT(TXT::new(vec![name.to_string()])),
    )
}

async fn serve(receiver: &mut mpsc::Receiver<Exchange>, mut message: Message) -> Message {
    let Exchange { wire, reply } = receiver.recv().await.unwrap();
    let query = Message::from_vec(&wire).unwrap();
    message.metadata.id = query.metadata.id;
    reply.send(Ok(message.to_vec().unwrap())).unwrap();
    query
}

#[tokio::test(flavor = "current_thread")]
async fn transport_scopes_answers_to_the_queried_owner() {
    let (transport, mut receiver) = transport();
    let mut message = support::response(
        "alice.example.test.",
        RecordType::TXT,
        vec![
            txt("alice.example.test."),
            txt("bob.example.test."),
            txt("ALICE.example.test."),
        ],
        vec![],
        ResponseCode::NoError,
    );
    message.insert_additionals(vec![txt("carol.example.test.")]);
    let mut stream = transport.send(request(1, "alice.example.test.", RecordType::TXT));
    let (response, _) = tokio::join!(stream.next(), serve(&mut receiver, message));
    let response = response.unwrap().unwrap();
    assert_eq!(response.answers.len(), 2);
    assert!(response.answers.iter().all(|r| {
        r.name
            .to_ascii()
            .eq_ignore_ascii_case("alice.example.test.")
    }));
    assert!(response.additionals.is_empty());
}

#[tokio::test(flavor = "current_thread")]
#[allow(deprecated)]
async fn transport_drops_sha1_signatures() {
    use hickory_net::proto::{
        dnssec::rdata::{DNSSECRData, RRSIG, SigInput},
        rr::SerialNumber,
    };
    let (transport, mut receiver) = transport();
    let name = "alice.example.test.";
    let signature = |algorithm| {
        let input = SigInput {
            type_covered: RecordType::TXT,
            algorithm,
            num_labels: 3,
            original_ttl: 300,
            sig_expiration: SerialNumber::new(2),
            sig_inception: SerialNumber::new(1),
            key_tag: 1,
            signer_name: Name::from_ascii("example.test.").unwrap(),
        };
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0; 8]))),
        )
    };
    let message = support::response(
        name,
        RecordType::TXT,
        vec![
            txt(name),
            signature(Algorithm::RSASHA1),
            signature(Algorithm::RSASHA1NSEC3SHA1),
            signature(Algorithm::ED25519),
        ],
        vec![signature(Algorithm::RSASHA1)],
        ResponseCode::NoError,
    );
    let mut stream = transport.send(request(1, name, RecordType::TXT));
    let (response, _) = tokio::join!(stream.next(), serve(&mut receiver, message));
    let response = response.unwrap().unwrap();
    let algorithms: Vec<_> = response
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.input().algorithm),
            _ => None,
        })
        .collect();
    assert_eq!(algorithms, [Algorithm::ED25519]);
    assert_eq!(response.answers.len(), 2);
    assert!(response.authorities.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn transport_drops_sha1_digests() {
    use hickory_net::proto::dnssec::rdata::{DNSSECRData, DS};
    let (transport, mut receiver) = transport();
    let ds = |name, digest_type, len| {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            300,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                1,
                Algorithm::ED25519,
                digest_type,
                vec![0; len],
            ))),
        )
    };
    let digests = |section: &[Record]| -> Vec<_> {
        section
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::DS(ds)) => Some((r.name.to_ascii(), ds.digest_type())),
                _ => None,
            })
            .collect()
    };
    // A stronger digest in the authority section does not vouch for the
    // answer's SHA-1 digest; an unsupported digest type is not stronger.
    let authorities = || {
        vec![
            ds("mixed.test.", DigestType::SHA1, 20),
            ds("mixed.test.", DigestType::SHA256, 32),
            ds("legacy.test.", DigestType::SHA1, 20),
            ds("legacy.test.", DigestType::SHA256, 32),
            ds("gost.test.", DigestType::SHA1, 20),
            ds("gost.test.", DigestType::Unknown(3), 32),
        ]
    };
    let kept = [
        ("mixed.test.".to_string(), DigestType::SHA1),
        ("mixed.test.".to_string(), DigestType::SHA256),
        ("legacy.test.".to_string(), DigestType::SHA1),
        ("legacy.test.".to_string(), DigestType::SHA256),
        ("gost.test.".to_string(), DigestType::Unknown(3)),
    ];
    let mixed = kept[..2].to_vec();
    for (id, name, answers, expected) in [
        (
            1,
            "mixed.test.",
            vec![
                ds("mixed.test.", DigestType::SHA1, 20),
                ds("mixed.test.", DigestType::SHA256, 32),
            ],
            mixed.clone(),
        ),
        (
            2,
            "legacy.test.",
            vec![ds("legacy.test.", DigestType::SHA1, 20)],
            vec![],
        ),
    ] {
        let message = support::response(
            name,
            RecordType::DS,
            answers,
            authorities(),
            ResponseCode::NoError,
        );
        let mut stream = transport.send(request(id, name, RecordType::DS));
        let (response, _) = tokio::join!(stream.next(), serve(&mut receiver, message));
        let response = response.unwrap().unwrap();
        assert_eq!(digests(&response.answers), expected);
        assert_eq!(response.answers.len(), expected.len());
        assert_eq!(digests(&response.authorities), kept);
        assert_eq!(response.authorities.len(), kept.len());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn transport_coalesces_identical_questions() {
    let (transport, mut receiver) = transport();
    let message = support::response(
        "alice.example.test.",
        RecordType::TXT,
        vec![txt("alice.example.test.")],
        vec![],
        ResponseCode::NoError,
    );
    let mut first = transport.send(request(1, "alice.example.test.", RecordType::TXT));
    let mut second = transport.send(request(2, "ALICE.example.test.", RecordType::TXT));
    let (first, second, _) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(first.next(), second.next(), serve(&mut receiver, message))
    })
    .await
    .unwrap();
    assert_eq!(first.unwrap().unwrap().id, 1);
    assert_eq!(second.unwrap().unwrap().id, 2);
    assert_eq!(
        transport.count.load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn shared_questions_count_against_the_query_budget() {
    let (mut transport, mut receiver) = transport();
    transport.max_queries = 2;
    let message = support::response(
        "alice.example.test.",
        RecordType::TXT,
        vec![txt("alice.example.test.")],
        vec![],
        ResponseCode::NoError,
    );
    let mut first = transport.send(request(1, "alice.example.test.", RecordType::TXT));
    let mut second = transport.send(request(2, "alice.example.test.", RecordType::TXT));
    let (first, second, _) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(first.next(), second.next(), serve(&mut receiver, message))
    })
    .await
    .unwrap();
    assert!(first.unwrap().is_ok());
    assert!(second.unwrap().is_ok());
    let third = transport
        .send(request(3, "alice.example.test.", RecordType::TXT))
        .next()
        .await
        .unwrap();
    assert!(
        third
            .unwrap_err()
            .to_string()
            .contains("query limit exceeded")
    );
    assert!(receiver.try_recv().is_err());
}

#[test]
fn root_anchors_match_iana_2017_and_2024_ds_digests() {
    let anchors = TrustAnchors::default();
    assert_eq!(anchors.len(), 2);
    use base64::{Engine, engine::general_purpose::STANDARD};
    for (tag, digest, public_key) in [
        (
            20326,
            "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
            "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
        ),
        (
            38696,
            "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
            "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
        ),
    ] {
        let public_key =
            PublicKeyBuf::new(STANDARD.decode(public_key).unwrap(), Algorithm::RSASHA256);
        assert!(anchors.contains_with_name(&public_key, &Name::root().into()));
        let key = DNSKEY::from_key(&public_key);
        assert_eq!(key.calculate_key_tag().unwrap(), tag);
        let actual: String = key
            .to_digest(&Name::root(), DigestType::SHA256)
            .unwrap()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(actual, digest);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_runtime_cannot_open_tcp_or_udp() {
    let address = "127.0.0.1:53".parse().unwrap();
    assert!(
        NoNetworkRuntime
            .connect_tcp(address, None, None)
            .await
            .is_err()
    );
    assert!(NoNetworkRuntime.bind_udp(address, address).await.is_err());
}

#[test]
fn wire_fixtures_match_the_signed_test_zones() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (anchor, messages) = support::fixtures();
    let messages: std::collections::BTreeMap<_, _> = messages
        .into_iter()
        .map(|(name, message)| (name, STANDARD.encode(message.to_vec().unwrap())))
        .collect();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../../test/support/zones.json")).unwrap();
    assert_eq!(
        serde_json::json!({"anchor": anchor, "messages": messages}),
        expected
    );
}
