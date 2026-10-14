use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::{Stream, StreamExt, stream};
use hickory_net::{
    DnsError, NetError,
    dnssec::DnssecDnsHandle,
    proto::{
        dnssec::{Proof, TrustAnchors, rdata::DNSSECRData},
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Edns, OpCode, Query, ResponseCode},
        rr::{
            Name, RData, RecordType,
            rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
        },
    },
    runtime::{RuntimeProvider, TokioRuntimeProvider},
    xfer::DnsHandle,
};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

pub struct Exchange {
    pub wire: Vec<u8>,
    pub reply: oneshot::Sender<Result<Vec<u8>, String>>,
}

#[derive(Clone)]
pub struct NoNetworkRuntime;

impl RuntimeProvider for NoNetworkRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
    fn create_handle(&self) -> Self::Handle {
        TokioRuntimeProvider::new().create_handle()
    }
    fn connect_tcp(
        &self,
        _: SocketAddr,
        _: Option<SocketAddr>,
        _: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        Box::pin(async { Err(io::Error::other("native networking disabled")) })
    }
    fn bind_udp(
        &self,
        _: SocketAddr,
        _: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        Box::pin(async { Err(io::Error::other("native networking disabled")) })
    }
}

#[derive(Clone)]
pub struct Transport {
    pub requests: mpsc::Sender<Exchange>,
    pub count: Arc<AtomicUsize>,
    pub max_queries: usize,
}

impl DnsHandle for Transport {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = NoNetworkRuntime;

    fn send(&self, request: DnsRequest) -> Self::Response {
        Box::pin(stream::once(self.clone().exchange(request)))
    }
}

impl Transport {
    async fn exchange(self, mut request: DnsRequest) -> Result<DnsResponse, NetError> {
        if self.count.fetch_add(1, Ordering::Relaxed) >= self.max_queries {
            return Err(NetError::from("query limit exceeded"));
        }
        let Some(question) = request.queries.first().cloned() else {
            return Err(NetError::from("request has no question"));
        };
        request.metadata.checking_disabled = true;
        request.metadata.authentic_data = false;
        request.metadata.recursion_desired = true;
        let edns = request.edns.get_or_insert_with(Edns::new);
        edns.options_mut().options.clear();
        edns.enable_dnssec();
        edns.options_mut().options.push((
            EdnsCode::Subnet,
            EdnsOption::Subnet(ClientSubnet::new(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
                0,
                0,
            )),
        ));
        let wire = request.to_vec()?;
        let (reply, receiver) = oneshot::channel();
        self.requests
            .send(Exchange { wire, reply })
            .await
            .map_err(|_| NetError::from("cancelled"))?;
        let bytes = receiver
            .await
            .map_err(|_| NetError::from("cancelled"))?
            .map_err(NetError::from)?;
        if bytes.len() > 65535 {
            return Err(NetError::from("response limit exceeded"));
        }
        let mut response = DnsResponse::from_buffer(bytes)?;
        if response.id != request.id
            || response.op_code != OpCode::Query
            || response.queries != request.queries
            || response.truncation
        {
            return Err(NetError::from("response does not match request"));
        }
        if response.answers.len() + response.authorities.len() + response.additionals.len() > 256 {
            return Err(NetError::from("record limit exceeded"));
        }
        let mut counts = HashMap::new();
        for rr in response
            .answers
            .iter()
            .chain(&response.authorities)
            .chain(&response.additionals)
        {
            let (kind, limit) = match &rr.data {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => (sig.input().type_covered, 16),
                RData::DNSSEC(DNSSECRData::DNSKEY(_)) => (RecordType::DNSKEY, 32),
                _ => continue,
            };
            let count = counts
                .entry((rr.name.clone(), rr.record_type(), kind))
                .or_insert(0);
            *count += 1;
            if *count > limit {
                return Err(NetError::from("validation work limit exceeded"));
            }
        }
        // Answers are scoped to the queried owner; aliases are followed by the engine.
        response.answers.retain(|r| r.name == question.name);
        response.additionals.clear();
        if question.query_type != RecordType::CNAME
            && response
                .answers
                .iter()
                .any(|r| r.record_type() == RecordType::CNAME)
        {
            response.authorities.clear();
        }
        response.metadata.authentic_data = false;
        Ok(response)
    }
}

#[derive(Debug, Serialize)]
pub struct Record {
    pub name: String,
    pub record_type: u16,
    pub ttl: u32,
    pub data: String,
    pub txt: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct Outcome {
    pub status: &'static str,
    pub canonical_name: String,
    pub records: Vec<Record>,
    pub aliases: Vec<Record>,
}

fn record(rr: &hickory_net::proto::rr::Record) -> Record {
    Record {
        name: rr.name.to_ascii(),
        record_type: rr.record_type().into(),
        ttl: rr.ttl,
        data: match &rr.data {
            RData::CNAME(target) => target.0.to_ascii(),
            data => data.to_string(),
        },
        txt: match &rr.data {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .flat_map(|s| s.iter().copied())
                    .collect(),
            ),
            _ => None,
        },
    }
}

fn status(proof: Proof) -> &'static str {
    match proof {
        Proof::Secure => "secure",
        Proof::Insecure => "insecure",
        Proof::Bogus => "bogus",
        _ => "indeterminate",
    }
}

pub async fn resolve(
    name: Name,
    kind: RecordType,
    transport: Transport,
    anchors: TrustAnchors,
) -> Outcome {
    let handle = DnssecDnsHandle::with_trust_anchor(transport, Arc::new(anchors))
        .validation_cache_size(256)
        .nsec3_iteration_limits(Some(150), Some(150));
    let mut owner = name;
    let mut seen = HashSet::new();
    let mut aliases = Vec::new();
    let failure = |status, owner: &Name, aliases| Outcome {
        status,
        canonical_name: owner.to_ascii(),
        records: vec![],
        aliases,
    };
    for _ in 0..8 {
        if !seen.insert(owner.clone()) {
            return failure("aliasLoop", &owner, aliases);
        }
        let mut options = DnsRequestOptions::default();
        options.max_request_depth = 16;
        let response = handle
            .lookup(Query::query(owner.clone(), kind), options)
            .next()
            .await;
        let response = match response {
            Some(Ok(response)) => response,
            Some(Err(NetError::Dns(DnsError::Nsec { proof, .. }))) => {
                return failure(
                    if proof == Proof::Secure {
                        "noRecords"
                    } else {
                        status(proof)
                    },
                    &owner,
                    aliases,
                );
            }
            Some(Err(NetError::Dns(DnsError::DnssecBogus))) => {
                return failure("bogus", &owner, aliases);
            }
            _ => return failure("indeterminate", &owner, aliases),
        };
        // Only records at the current owner may supply data or authorize the next CNAME hop.
        let records: Vec<_> = response
            .answers
            .iter()
            .filter(|r| r.name == owner && r.record_type() == kind)
            .collect();
        let cnames: Vec<_> = response
            .answers
            .iter()
            .filter(|r| r.name == owner && r.record_type() == RecordType::CNAME)
            .collect();
        // Expanded records are not accepted.
        let expanded = |covered: RecordType| {
            response.answers.iter().any(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                    r.name == owner
                        && r.proof == Proof::Secure
                        && sig.input().type_covered == covered
                        && sig.input().num_labels < owner.num_labels()
                }
                _ => false,
            })
        };
        if records.len() > 64 {
            return failure("responseTooLarge", &owner, aliases);
        }
        if kind != RecordType::CNAME && !cnames.is_empty() {
            if cnames.len() != 1 || !records.is_empty() {
                return failure("aliasAmbiguous", &owner, aliases);
            }
            let cname = cnames[0];
            if cname.proof != Proof::Secure {
                return failure(status(cname.proof), &owner, aliases);
            }
            if expanded(RecordType::CNAME) {
                return failure("bogus", &owner, aliases);
            }
            let RData::CNAME(target) = &cname.data else {
                return failure("indeterminate", &owner, aliases);
            };
            aliases.push(record(cname));
            owner = target.0.clone();
            continue;
        }
        if response.response_code != ResponseCode::NoError {
            return failure(
                if response.response_code == ResponseCode::NXDomain {
                    "noRecords"
                } else {
                    "queryFailed"
                },
                &owner,
                aliases,
            );
        }
        if records.is_empty() {
            return failure("noRecords", &owner, aliases);
        }
        if let Some(rr) = records.iter().find(|r| r.proof != Proof::Secure) {
            return failure(status(rr.proof), &owner, aliases);
        }
        if expanded(kind) {
            return failure("bogus", &owner, aliases);
        }
        return Outcome {
            status: "secure",
            canonical_name: owner.to_ascii(),
            records: records.into_iter().map(record).collect(),
            aliases,
        };
    }
    failure("aliasTooLong", &owner, aliases)
}
