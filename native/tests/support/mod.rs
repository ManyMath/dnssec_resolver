use hickory_net::proto::{
    dnssec::{
        Algorithm, DigestType, Nsec3HashAlgorithm, SigningKey, TBS,
        crypto::Ed25519SigningKey,
        rdata::{DNSKEY, DNSSECRData, DS, NSEC, NSEC3, RRSIG, SigInput},
    },
    op::{Message, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType, SerialNumber,
        rdata::{CNAME, NS, NULL, SOA, TXT},
    },
};
use ring::signature::Ed25519KeyPair;
use std::collections::BTreeMap;

// RFC 1982 serial arithmetic.
const INCEPTION: u32 = 1_700_000_000;
const EXPIRATION: u32 = 3_800_000_000;
const FUTURE: u32 = 3_700_000_000;

pub struct Zone {
    name: Name,
    key: Ed25519SigningKey,
    pub dnskey: DNSKEY,
}

impl Zone {
    pub fn new(name: &str, seed: u8) -> Self {
        let key = Ed25519SigningKey::from_ed25519(
            Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap(),
        );
        let dnskey = DNSKEY::from_key(&key.to_public_key().unwrap());
        Self {
            name: Name::from_ascii(name).unwrap(),
            key,
            dnskey,
        }
    }

    pub fn sign(
        &self,
        records: Vec<Record>,
        inception: u32,
        expiration: u32,
        labels: Option<u8>,
    ) -> Vec<Record> {
        let owner = &records[0].name;
        let input = SigInput {
            type_covered: records[0].record_type(),
            algorithm: Algorithm::ED25519,
            num_labels: labels.unwrap_or(owner.num_labels()),
            original_ttl: records[0].ttl,
            sig_expiration: SerialNumber::new(expiration),
            sig_inception: SerialNumber::new(inception),
            key_tag: self.dnskey.calculate_key_tag().unwrap(),
            signer_name: self.name.clone(),
        };
        let tbs = TBS::from_input(owner, DNSClass::IN, &input, records.iter()).unwrap();
        let sig = self.key.sign(&tbs).unwrap();
        let signature = Record::from_rdata(
            owner.clone(),
            records[0].ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))),
        );
        records.into_iter().chain([signature]).collect()
    }

    pub fn signed(&self, records: Vec<Record>) -> Vec<Record> {
        self.sign(records, INCEPTION, EXPIRATION, None)
    }

    fn keys(&self) -> Vec<Record> {
        self.signed(vec![rr(
            &self.name.to_utf8(),
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        )])
    }

    fn delegation(&self, child: &Self) -> Vec<Record> {
        self.signed(vec![rr(
            &child.name.to_utf8(),
            RData::DNSSEC(DNSSECRData::DS(
                DS::from_key(
                    &child.key.to_public_key().unwrap(),
                    &child.name,
                    DigestType::SHA256,
                )
                .unwrap(),
            )),
        )])
    }

    fn soa(&self) -> Vec<Record> {
        self.signed(vec![rr(
            &self.name.to_utf8(),
            RData::SOA(SOA::new(
                self.name.clone(),
                self.name.clone(),
                1,
                60,
                60,
                3600,
                60,
            )),
        )])
    }
}

fn rr(name: &str, data: RData) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), 300, data)
}
fn txt(name: &str) -> Record {
    rr(
        name,
        RData::TXT(txt_data(vec![
            "oa1:xmr ".into(),
            "recipient_address=valid;".into(),
        ])),
    )
}

pub fn response(
    name: &str,
    kind: RecordType,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    code: ResponseCode,
) -> Message {
    let mut message = Message::query().into_response();
    message.metadata.id = 0;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    message.metadata.response_code = code;
    message.metadata.authentic_data = true;
    message.insert_answers(answers);
    message.insert_authorities(authorities);
    message
}

pub fn fixtures() -> (String, BTreeMap<String, Message>) {
    let root = Zone::new(".", 1);
    let tld = Zone::new("test.", 2);
    let zone = Zone::new("example.test.", 3);
    let other = Zone::new("other.test.", 4);
    let bad_ds = Zone::new("bad-ds.test.", 5);
    let anchor = format!(". 300 IN DNSKEY {}\n", root.dnskey);
    let mut messages = BTreeMap::new();
    {
        let mut put = |name: &str, kind, answers, authorities| {
            messages.insert(
                format!("{name}:{}", u16::from(kind)),
                response(name, kind, answers, authorities, ResponseCode::NoError),
            );
        };
        for z in [&root, &tld, &zone, &other, &bad_ds] {
            put(&z.name.to_utf8(), RecordType::DNSKEY, z.keys(), vec![]);
            put(
                &z.name.to_utf8(),
                RecordType::NS,
                z.signed(vec![rr(&z.name.to_utf8(), RData::NS(NS(z.name.clone())))]),
                vec![],
            );
        }
        put("test.", RecordType::DS, root.delegation(&tld), vec![]);
        put(
            "example.test.",
            RecordType::DS,
            tld.delegation(&zone),
            vec![],
        );
        put(
            "other.test.",
            RecordType::DS,
            tld.delegation(&other),
            vec![],
        );
        put(
            "bad-ds.test.",
            RecordType::DS,
            tld.delegation(&Zone::new("bad-ds.test.", 99)),
            vec![],
        );
        put(
            "alice.bad-ds.test.",
            RecordType::TXT,
            bad_ds.signed(vec![txt("alice.bad-ds.test.")]),
            vec![],
        );
        for name in ["alice.example.test.", "bob.other.test."] {
            let signer = if name.contains("other") {
                &other
            } else {
                &zone
            };
            put(
                name,
                RecordType::TXT,
                signer.signed(vec![txt(name)]),
                vec![],
            );
        }
        put(
            "alias.example.test.",
            RecordType::TXT,
            zone.signed(vec![rr(
                "alias.example.test.",
                RData::CNAME(CNAME(Name::from_ascii("bob.other.test.").unwrap())),
            )]),
            vec![],
        );
        let idn = "xn--caf-dma.other.test.";
        put(
            "xn--bcher-kva.example.test.",
            RecordType::TXT,
            zone.signed(vec![rr(
                "xn--bcher-kva.example.test.",
                RData::CNAME(CNAME(Name::from_ascii(idn).unwrap())),
            )]),
            vec![],
        );
        put(idn, RecordType::TXT, other.signed(vec![txt(idn)]), vec![]);
        for (name, target) in [
            ("loop.example.test.", "loop.example.test."),
            ("one.example.test.", "two.example.test."),
            ("two.example.test.", "one.example.test."),
        ] {
            put(
                name,
                RecordType::TXT,
                zone.signed(vec![rr(
                    name,
                    RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
                )]),
                vec![],
            );
        }
        let tampered = "tampered.example.test.";
        let mut records = zone.signed(vec![txt(tampered)]);
        records[0].data = RData::TXT(txt_data(vec!["oa1:xmr recipient_address=attacker;".into()]));
        put(tampered, RecordType::TXT, records, vec![]);
        put(
            "expired.example.test.",
            RecordType::TXT,
            zone.sign(
                vec![txt("expired.example.test.")],
                1_600_000_000,
                1_600_000_300,
                None,
            ),
            vec![],
        );
        put(
            "future.example.test.",
            RecordType::TXT,
            zone.sign(
                vec![txt("future.example.test.")],
                FUTURE,
                FUTURE + 300,
                None,
            ),
            vec![],
        );
        put(
            "forged.example.test.",
            RecordType::TXT,
            other.signed(vec![txt("forged.example.test.")]),
            vec![],
        );
        put(
            "unsigned.test.",
            RecordType::TXT,
            vec![txt("unsigned.test.")],
            vec![],
        );
        put(
            "unsigned.test.",
            RecordType::NS,
            vec![rr(
                "unsigned.test.",
                RData::NS(NS(Name::from_ascii("ns.unsigned.test.").unwrap())),
            )],
            vec![],
        );
        let mut no_ds = tld.soa();
        no_ds.extend(tld.signed(vec![rr(
            "unsigned.test.",
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
                Name::from_ascii("zzz.test.").unwrap(),
                [RecordType::NS],
            ))),
        )]));
        put("unsigned.test.", RecordType::DS, vec![], no_ds);
        put(
            "wild.example.test.",
            RecordType::TXT,
            zone.sign(
                vec![txt("wild.example.test.")],
                INCEPTION,
                EXPIRATION,
                Some(2),
            ),
            vec![],
        );
        for (name, target, valid) in [
            (
                "alias-wild-valid.example.test.",
                "wild-valid.other.test.",
                true,
            ),
            (
                "alias-wild-missing.example.test.",
                "wild.other.test.",
                false,
            ),
        ] {
            let mut answer = zone.sign(
                vec![rr(
                    name,
                    RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
                )],
                INCEPTION,
                EXPIRATION,
                Some(2),
            );
            let target_answer = other.sign(vec![txt(target)], INCEPTION, EXPIRATION, Some(2));
            answer.extend(target_answer.clone());
            let denial = |signer: &Zone| {
                signer.signed(vec![rr(
                    &format!("*.{}", signer.name),
                    RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
                        Name::from_ascii(format!("zzz.{}", signer.name)).unwrap(),
                        [RecordType::TXT],
                    ))),
                )])
            };
            let mut proofs = denial(&zone);
            if valid {
                proofs.extend(denial(&other));
            }
            put(name, RecordType::TXT, answer, proofs);
            put(
                target,
                RecordType::TXT,
                target_answer,
                if valid { denial(&other) } else { vec![] },
            );
        }
        let mut nodata = zone.soa();
        let mut denial = zone.soa();
        denial.extend(zone.signed(vec![rr(
            "*.example.test.",
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
                Name::from_ascii("zzz.example.test.").unwrap(),
                [RecordType::TXT],
            ))),
        )]));
        put(
            "wild-valid.example.test.",
            RecordType::TXT,
            zone.sign(
                vec![txt("wild-valid.example.test.")],
                INCEPTION,
                EXPIRATION,
                Some(2),
            ),
            denial,
        );
        nodata.extend(zone.signed(vec![rr(
            "empty.example.test.",
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
                Name::from_ascii("zzz.example.test.").unwrap(),
                [RecordType::A],
            ))),
        )]));
        put("empty.example.test.", RecordType::TXT, vec![], nodata);
        for (name, types, signer) in [
            ("nsec3.example.test.", vec![RecordType::A], &zone),
            ("unsigned3.test.", vec![RecordType::NS], &tld),
        ] {
            let hash = Nsec3HashAlgorithm::SHA1
                .hash(&[], &Name::from_ascii(name).unwrap(), 0)
                .unwrap();
            let owner = format!(
                "{}.{}",
                data_encoding::BASE32_DNSSEC.encode(hash.as_ref()),
                signer.name
            );
            let nsec3 = rr(
                &owner,
                RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                    Nsec3HashAlgorithm::SHA1,
                    false,
                    0,
                    vec![],
                    hash.as_ref().to_vec(),
                    types,
                ))),
            );
            let mut authority = signer.soa();
            authority.extend(signer.signed(vec![nsec3]));
            let insecure = name.starts_with("unsigned");
            put(
                name,
                if insecure {
                    RecordType::DS
                } else {
                    RecordType::TXT
                },
                vec![],
                authority,
            );
            if insecure {
                put(
                    name,
                    RecordType::NS,
                    vec![rr(
                        name,
                        RData::NS(NS(Name::from_ascii("ns.unsigned3.test.").unwrap())),
                    )],
                    vec![],
                );
                put(name, RecordType::TXT, vec![txt(name)], vec![]);
            }
        }
        for (name, opt_out) in [
            ("unsigned-optout.test.", true),
            ("unsigned-no-optout.test.", false),
        ] {
            let hash = Nsec3HashAlgorithm::SHA1.hash(&[], &tld.name, 0).unwrap();
            let owner = format!(
                "{}.{}",
                data_encoding::BASE32_DNSSEC.encode(hash.as_ref()),
                tld.name
            );
            let mut authority = tld.soa();
            authority.extend(tld.signed(vec![rr(
                &owner,
                RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                    Nsec3HashAlgorithm::SHA1,
                    opt_out,
                    0,
                    vec![],
                    hash.as_ref().to_vec(),
                    [RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
                ))),
            )]));
            put(name, RecordType::DS, vec![], authority);
            put(
                name,
                RecordType::NS,
                vec![rr(
                    name,
                    RData::NS(NS(Name::from_ascii(format!("ns.{name}")).unwrap())),
                )],
                vec![],
            );
            put(name, RecordType::TXT, vec![txt(name)], vec![]);
        }
        let mut inflated = zone.signed(vec![txt("ttl.example.test.")]);
        inflated[0].ttl = u32::MAX;
        put("ttl.example.test.", RecordType::TXT, inflated, vec![]);
        let mut ambiguous = zone.signed(vec![
            rr(
                "ambiguous.example.test.",
                RData::CNAME(CNAME(Name::from_ascii("bob.other.test.").unwrap())),
            ),
            rr(
                "ambiguous.example.test.",
                RData::CNAME(CNAME(Name::from_ascii("alice.example.test.").unwrap())),
            ),
        ]);
        ambiguous.extend(zone.signed(vec![txt("ambiguous.example.test.")]));
        put(
            "ambiguous.example.test.",
            RecordType::TXT,
            ambiguous,
            vec![],
        );
        for i in 0..9 {
            let name = format!("chain{i}.example.test.");
            put(
                &name,
                RecordType::TXT,
                zone.signed(vec![rr(
                    &name,
                    RData::CNAME(CNAME(
                        Name::from_ascii(format!("chain{}.example.test.", i + 1)).unwrap(),
                    )),
                )]),
                vec![],
            );
        }
        let mut dname = zone.signed(vec![rr(
            "redirect.example.test.",
            RData::Unknown {
                code: RecordType::DNAME,
                rdata: NULL::with(b"\x05other\x04test\x00".to_vec()),
            },
        )]);
        dname.push(rr(
            "bob.redirect.example.test.",
            RData::CNAME(CNAME(Name::from_ascii("bob.other.test.").unwrap())),
        ));
        dname.extend(other.signed(vec![txt("bob.other.test.")]));
        put("bob.redirect.example.test.", RecordType::TXT, dname, vec![]);
        put(
            "multi.example.test.",
            RecordType::TXT,
            zone.signed(
                ["one", "two", "three"]
                    .map(|part| {
                        rr(
                            "multi.example.test.",
                            RData::TXT(txt_data(vec![format!("oa1:xmr part={part};")])),
                        )
                    })
                    .to_vec(),
            ),
            vec![],
        );
        let nsec = |owner: &str, next: &str, types: Vec<RecordType>| {
            rr(
                owner,
                RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
                    Name::from_ascii(next).unwrap(),
                    types,
                ))),
            )
        };
        let mut expanded_alias = zone.soa();
        expanded_alias.extend(zone.signed(vec![nsec(
            "*.example.test.",
            "zzz.example.test.",
            vec![RecordType::CNAME],
        )]));
        put(
            "expanded-alias.example.test.",
            RecordType::TXT,
            zone.sign(
                vec![rr(
                    "expanded-alias.example.test.",
                    RData::CNAME(CNAME(Name::from_ascii("bob.other.test.").unwrap())),
                )],
                INCEPTION,
                EXPIRATION,
                Some(2),
            ),
            expanded_alias,
        );
        let mut other_nodata = other.soa();
        other_nodata.extend(other.signed(vec![nsec(
            "empty.other.test.",
            "zzz.other.test.",
            vec![RecordType::A],
        )]));
        put(
            "empty.other.test.",
            RecordType::TXT,
            vec![],
            other_nodata.clone(),
        );
        for (name, target, authority) in [
            (
                "alias-empty.example.test.",
                "empty.other.test.",
                other_nodata,
            ),
            ("alias-nodata.example.test.", "empty.example.test.", vec![]),
        ] {
            put(
                name,
                RecordType::TXT,
                zone.signed(vec![rr(
                    name,
                    RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
                )]),
                authority,
            );
        }
        // Delegations whose DS answer also carries a DS RRset owned by another name.
        for (name, seed, ds_owner, signer, own_ds) in [
            ("sibling.test.", 11, "neighbour.test.", &tld, true),
            ("cousin.test.", 12, "cousin.", &root, true),
            ("orphan.test.", 13, "neighbour.test.", &tld, false),
        ] {
            let child = Zone::new(name, seed);
            let served = Zone::new(name, seed + 50);
            let ds = DS::from_key(
                &served.key.to_public_key().unwrap(),
                &served.name,
                DigestType::SHA256,
            )
            .unwrap();
            let mut answer = if own_ds {
                tld.delegation(&child)
            } else {
                vec![]
            };
            answer.extend(signer.signed(vec![rr(ds_owner, RData::DNSSEC(DNSSECRData::DS(ds)))]));
            put(name, RecordType::DS, answer, vec![]);
            put(name, RecordType::DNSKEY, served.keys(), vec![]);
            let leaf = format!("alice.{name}");
            put(
                &leaf,
                RecordType::TXT,
                served.signed(vec![txt(&leaf)]),
                vec![],
            );
        }
        let legacy = Zone::new("legacy.test.", 14);
        let digest = legacy
            .dnskey
            .to_digest(&legacy.name, DigestType::SHA256)
            .unwrap();
        put(
            "legacy.test.",
            RecordType::DS,
            tld.signed(vec![rr(
                "legacy.test.",
                RData::DNSSEC(DNSSECRData::DS(DS::new(
                    legacy.dnskey.calculate_key_tag().unwrap(),
                    Algorithm::Unknown(200),
                    DigestType::SHA256,
                    digest.as_ref().to_vec(),
                ))),
            )]),
            vec![],
        );
        put("legacy.test.", RecordType::DNSKEY, legacy.keys(), vec![]);
        put(
            "alice.legacy.test.",
            RecordType::TXT,
            legacy.signed(vec![txt("alice.legacy.test.")]),
            vec![],
        );
    }
    let mut nxdomain = zone.soa();
    nxdomain.extend(zone.signed(vec![rr(
        "example.test.",
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
            Name::from_ascii("empty.example.test.").unwrap(),
            [RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
        ))),
    )]));
    nxdomain.extend(zone.signed(vec![rr(
        "empty.example.test.",
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
            Name::from_ascii("zzz.example.test.").unwrap(),
            [RecordType::A],
        ))),
    )]));
    messages.insert(
        format!("missing.example.test.:{}", u16::from(RecordType::TXT)),
        response(
            "missing.example.test.",
            RecordType::TXT,
            vec![],
            nxdomain,
            ResponseCode::NXDomain,
        ),
    );

    let apex_hash = Nsec3HashAlgorithm::SHA1.hash(&[], &zone.name, 0).unwrap();
    let apex_owner = format!(
        "{}.{}",
        data_encoding::BASE32_DNSSEC.encode(apex_hash.as_ref()),
        zone.name
    );
    let mut nxdomain3 = zone.soa();
    nxdomain3.extend(zone.signed(vec![rr(
        &apex_owner,
        RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            vec![],
            apex_hash.as_ref().to_vec(),
            [RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
        ))),
    )]));
    messages.insert(
        format!("missing3.example.test.:{}", u16::from(RecordType::TXT)),
        response(
            "missing3.example.test.",
            RecordType::TXT,
            vec![],
            nxdomain3,
            ResponseCode::NXDomain,
        ),
    );
    (anchor, messages)
}

fn txt_data(parts: Vec<String>) -> TXT {
    TXT::new(parts)
}
