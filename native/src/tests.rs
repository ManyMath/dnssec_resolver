use crate::engine::NoNetworkRuntime;
#[path = "../tests/support/mod.rs"]
pub(crate) mod support;
use hickory_net::{
    proto::{
        dnssec::{Algorithm, DigestType, PublicKeyBuf, TrustAnchors, rdata::DNSKEY},
        rr::Name,
    },
    runtime::RuntimeProvider,
};

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
