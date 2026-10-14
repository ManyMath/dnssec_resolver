use crate::engine::{self, Exchange, Outcome, Transport};
use base64::{Engine, engine::general_purpose::STANDARD};
use hickory_net::proto::{
    dnssec::TrustAnchors,
    rr::{Name, RecordType},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    ffi::{CString, c_char},
    panic::{self, AssertUnwindSafe},
    ptr, slice,
    str::FromStr,
    sync::{
        Arc, LazyLock, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

static JOBS: LazyLock<Mutex<HashMap<u64, Job>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static NEXT_JOB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
const MAX_JOBS: usize = 8;

fn jobs() -> MutexGuard<'static, HashMap<u64, Job>> {
    JOBS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn guarded<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

struct Job {
    deadline: Instant,
    requests: mpsc::Receiver<Exchange>,
    result: oneshot::Receiver<Outcome>,
    cancel: Option<oneshot::Sender<()>>,
    pending: HashMap<u64, oneshot::Sender<Result<Vec<u8>, String>>>,
    next_request: u64,
}

impl Drop for Job {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

struct ActiveGuard;
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Deserialize)]
struct Config {
    name: String,
    record_type: u16,
    timeout_ms: u64,
    max_queries: usize,
    trust_anchors: Option<String>,
}

fn valid_name(name: &str) -> bool {
    name.strip_suffix('.').is_some_and(|body| {
        !body.is_empty()
            && body.len() <= 253
            && body.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
    })
}

// A, CNAME, TXT, AAAA.
fn valid_type(record_type: u16) -> bool {
    matches!(record_type, 1 | 5 | 16 | 28)
}

fn start(config: &[u8]) -> Option<u64> {
    let config: Config = serde_json::from_slice(config).ok()?;
    if !valid_name(&config.name)
        || !valid_type(config.record_type)
        || !(1..=121_000).contains(&config.timeout_ms)
        || !(1..=128).contains(&config.max_queries)
    {
        return None;
    }
    let name = Name::from_ascii(&config.name).ok()?;
    let anchors = match config.trust_anchors {
        Some(text) if !text.trim().is_empty() => TrustAnchors::from_str(&text).ok()?,
        Some(_) => return None,
        None => TrustAnchors::default(),
    };
    if anchors.is_empty() {
        return None;
    }
    let mut jobs = jobs();
    let now = Instant::now();
    jobs.retain(|_, job| job.deadline > now);
    if jobs.len() >= MAX_JOBS
        || ACTIVE
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_JOBS).then_some(n + 1)
            })
            .is_err()
    {
        return None;
    }
    let (requests_tx, requests) = mpsc::channel(16);
    let (result_tx, result) = oneshot::channel();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let handle = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
    let transport = Transport {
        requests: requests_tx,
        count: Arc::new(AtomicUsize::new(0)),
        max_queries: config.max_queries,
    };
    let thread = std::thread::Builder::new().name("dnssec-validator".into()).spawn(move || {
        let _active = ActiveGuard;
        let failure = |status| Outcome { status, canonical_name: name.to_ascii(), records: vec![], aliases: vec![] };
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_time().build() else {
            let _ = result_tx.send(failure("unavailable")); return;
        };
        let outcome = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = cancel_rx => failure("cancelled"),
                _ = tokio::time::sleep(Duration::from_millis(config.timeout_ms)) => failure("timedOut"),
                value = engine::resolve(name.clone(), RecordType::from(config.record_type), transport, anchors) => value,
            }
        });
        let _ = result_tx.send(outcome);
    });
    if thread.is_err() {
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    jobs.insert(
        handle,
        Job {
            deadline: now + Duration::from_millis(config.timeout_ms),
            requests,
            result,
            cancel: Some(cancel_tx),
            pending: HashMap::new(),
            next_request: 1,
        },
    );
    Some(handle)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dnssec_start(config: *const u8, length: usize) -> u64 {
    if config.is_null() || length > 65536 {
        return 0;
    }
    // Dart owns this allocation until the synchronous FFI call returns.
    let config = unsafe { slice::from_raw_parts(config, length) };
    guarded(None, || start(config)).unwrap_or(0)
}

/// Non-null results must be passed to `dnssec_free` exactly once.
#[unsafe(no_mangle)]
pub extern "C" fn dnssec_poll(handle: u64) -> *mut c_char {
    guarded(ptr::null_mut(), || poll(handle))
}

fn poll(handle: u64) -> *mut c_char {
    let mut jobs = jobs();
    let event = match jobs.get_mut(&handle) {
        None => json!({"error": "unavailable"}),
        Some(job) => match job.result.try_recv() {
            Ok(outcome) => json!({"result": outcome}),
            Err(oneshot::error::TryRecvError::Closed) => json!({"error": "unavailable"}),
            Err(oneshot::error::TryRecvError::Empty) => {
                let Ok(request) = job.requests.try_recv() else {
                    return ptr::null_mut();
                };
                let id = job.next_request;
                job.next_request += 1;
                let event = json!({"query": STANDARD.encode(request.wire), "id": id});
                job.pending.insert(id, request.reply);
                event
            }
        },
    };
    CString::new(event.to_string()).map_or(ptr::null_mut(), CString::into_raw)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dnssec_answer(handle: u64, request: u64, bytes: *const u8, length: usize) {
    let bytes = (!bytes.is_null() && length <= 65535)
        // Dart owns this allocation until the synchronous FFI call returns.
        .then(|| unsafe { slice::from_raw_parts(bytes, length) });
    guarded((), || answer(handle, request, bytes));
}

fn answer(handle: u64, request: u64, bytes: Option<&[u8]>) {
    let reply = jobs()
        .get_mut(&handle)
        .and_then(|job| job.pending.remove(&request));
    if let Some(reply) = reply {
        let _ = reply.send(
            bytes
                .map(<[u8]>::to_vec)
                .ok_or_else(|| "transport failed".into()),
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dnssec_release(handle: u64) {
    guarded((), || drop(jobs().remove(&handle)));
}

/// Accepts only pointers returned by `dnssec_poll`, each exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dnssec_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support;
    use hickory_net::proto::{
        dnssec::rdata::{DNSSECRData, RRSIG, SigInput},
        op::{Message, ResponseCode},
        rr::{RData, Record, rdata::TXT},
    };
    use serde_json::Value;
    use std::{collections::BTreeMap, ffi::CStr};

    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait_for_workers() {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while ACTIVE.load(Ordering::SeqCst) > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(ACTIVE.load(Ordering::SeqCst), 0);
    }

    fn config(name: &str, record_type: u16, timeout_ms: u64, anchors: Option<&str>) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "name": name,
            "record_type": record_type,
            "timeout_ms": timeout_ms,
            "max_queries": 64,
            "trust_anchors": anchors,
        }))
        .unwrap()
    }

    fn start_ffi(config: &[u8]) -> u64 {
        unsafe { dnssec_start(config.as_ptr(), config.len()) }
    }

    fn next_event(handle: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let event = dnssec_poll(handle);
            if !event.is_null() {
                let value = serde_json::from_slice(unsafe { CStr::from_ptr(event) }.to_bytes());
                unsafe { dnssec_free(event) };
                return value.unwrap();
            }
            assert!(Instant::now() < deadline, "no native event");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    struct Fixtures {
        anchor: String,
        messages: BTreeMap<String, Message>,
    }

    impl Fixtures {
        fn new() -> Self {
            let (anchor, messages) = support::fixtures();
            Self { anchor, messages }
        }

        fn reply(&self, query: &Message) -> Message {
            let question = &query.queries[0];
            let name = question.name.to_lowercase().to_ascii();
            let kind = question.query_type;
            let mut message = self
                .messages
                .get(&format!("{name}:{}", u16::from(kind)))
                .cloned()
                .unwrap_or_else(|| {
                    support::response(&name, kind, vec![], vec![], ResponseCode::NoError)
                });
            message.metadata.id = query.metadata.id;
            message
        }

        fn resolve(&self, name: &str, mut reply: impl FnMut(&Message) -> Option<Vec<u8>>) -> Value {
            let handle = start_ffi(&config(name, 16, 30_000, Some(&self.anchor)));
            assert_ne!(handle, 0);
            loop {
                let event = next_event(handle);
                let Some(query) = event.get("query") else {
                    dnssec_release(handle);
                    return event;
                };
                let query = STANDARD.decode(query.as_str().unwrap()).unwrap();
                let id = event["id"].as_u64().unwrap();
                match reply(&Message::from_vec(&query).unwrap()) {
                    Some(bytes) => unsafe {
                        dnssec_answer(handle, id, bytes.as_ptr(), bytes.len())
                    },
                    None => unsafe { dnssec_answer(handle, id, ptr::null(), 0) },
                }
            }
        }
    }

    fn status(event: &Value) -> &str {
        event["result"]["status"].as_str().unwrap()
    }

    #[test]
    fn limits_concurrent_jobs_and_releases_cancelled_workers() {
        let _serial = serial();
        let config = br#"{"name":"alice.example.","record_type":16,"timeout_ms":60000,"max_queries":64,"trust_anchors":null}"#;
        let handles: Vec<_> = (0..8).map(|_| start(config).unwrap()).collect();
        assert!(start(config).is_none());
        for handle in handles {
            dnssec_release(handle);
        }
        wait_for_workers();
        assert!(jobs().is_empty());
        let handle = start(config).unwrap();
        dnssec_release(handle);
        wait_for_workers();
    }

    #[test]
    fn abandoned_jobs_do_not_permanently_exhaust_slots() {
        let _serial = serial();
        let config = br#"{"name":"alice.example.","record_type":16,"timeout_ms":100,"max_queries":64,"trust_anchors":null}"#;
        let abandoned: Vec<_> = (0..8).map(|_| start(config).unwrap()).collect();
        wait_for_workers();
        let replacement = start(config).expect("expired orphan slots must be reusable");
        for handle in abandoned {
            assert_ne!(replacement, handle);
            assert_eq!(next_event(handle), json!({"error": "unavailable"}));
            dnssec_release(handle);
        }
        assert!(jobs().contains_key(&replacement));
        dnssec_release(replacement);
        wait_for_workers();
        assert!(jobs().is_empty());
    }

    #[test]
    fn rejects_invalid_configuration_at_the_boundary() {
        let _serial = serial();
        let long = format!("{}.", vec!["a".repeat(63); 4].join("."));
        assert_eq!(long.len(), 256);
        for name in [
            "alice.example",
            ".",
            "",
            "a..example.",
            "a\\.b.example.",
            "a\\000.example.",
            "*.example.",
            "a b.example.",
            "café.example.",
            &format!("{}.example.", "a".repeat(64)),
            &long,
        ] {
            assert_eq!(start_ffi(&config(name, 16, 1000, None)), 0, "{name:?}");
        }
        for record_type in [0, 2, 41, 99, 128, 250, 255, 256, 65535] {
            assert_eq!(start_ffi(&config("a.example.", record_type, 1000, None)), 0);
        }
        for timeout in [0, 121_001] {
            assert_eq!(start_ffi(&config("a.example.", 16, timeout, None)), 0);
        }
        for anchors in ["", " \n", "; nothing\n", "not a key"] {
            assert_eq!(start_ffi(&config("a.example.", 16, 1000, Some(anchors))), 0);
        }
        for raw in [&b"{}"[..], b"null", b"\xff", br#"{"name":"a.example.","record_type":16,"timeout_ms":1000,"max_queries":0,"trust_anchors":null}"#, br#"{"name":"a.example.","record_type":16,"timeout_ms":1000,"max_queries":129,"trust_anchors":null}"#] {
            assert_eq!(start_ffi(raw), 0);
        }
        assert_eq!(unsafe { dnssec_start(ptr::null(), 10) }, 0);
        let oversized = vec![b' '; 65537];
        assert_eq!(start_ffi(&oversized), 0);
        assert!(jobs().is_empty());
        let maximal = format!("{}.{}.", vec!["a".repeat(63); 3].join("."), "b".repeat(61));
        assert_eq!(maximal.len(), 254);
        let handle = start_ffi(&config(&maximal, 16, 1000, None));
        assert_ne!(handle, 0);
        dnssec_release(handle);
        wait_for_workers();
    }

    #[test]
    fn stale_handles_and_requests_are_inert() {
        let _serial = serial();
        let handle = start_ffi(&config("a.example.", 16, 60_000, None));
        assert_ne!(handle, 0);
        let event = next_event(handle);
        let id = event["id"].as_u64().unwrap();
        let bytes = [0u8; 4];
        unsafe {
            dnssec_answer(handle, id + 1000, bytes.as_ptr(), bytes.len());
            dnssec_answer(handle + 1000, id, bytes.as_ptr(), bytes.len());
            dnssec_answer(handle, id, ptr::null(), 0);
            dnssec_answer(handle, id, bytes.as_ptr(), bytes.len());
        }
        loop {
            let event = next_event(handle);
            if let Some(id) = event["id"].as_u64() {
                unsafe { dnssec_answer(handle, id, bytes.as_ptr(), 65536) };
                continue;
            }
            assert_eq!(status(&event), "indeterminate");
            break;
        }
        dnssec_release(handle);
        dnssec_release(handle);
        assert_eq!(next_event(handle), json!({"error": "unavailable"}));
        unsafe { dnssec_free(ptr::null_mut()) };
        wait_for_workers();
    }

    #[test]
    fn deadline_and_release_stop_stalled_workers() {
        let _serial = serial();
        let handle = start_ffi(&config("a.example.", 16, 50, None));
        assert!(next_event(handle).get("query").is_some());
        let event = loop {
            let event = next_event(handle);
            if event.get("result").is_some() {
                break event;
            }
        };
        assert_eq!(status(&event), "timedOut");
        dnssec_release(handle);
        let handle = start_ffi(&config("a.example.", 16, 60_000, None));
        assert!(next_event(handle).get("query").is_some());
        dnssec_release(handle);
        wait_for_workers();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn validates_fixture_chain_through_the_ffi() {
        let _serial = serial();
        let fixtures = Fixtures::new();
        let event = fixtures.resolve("alias.example.test.", |q| fixtures.reply(q).to_vec().ok());
        assert_eq!(status(&event), "secure");
        assert_eq!(event["result"]["canonical_name"], "bob.other.test.");
        let txt: Vec<u8> =
            serde_json::from_value(event["result"]["records"][0]["txt"].clone()).unwrap();
        assert_eq!(txt, b"oa1:xmr recipient_address=valid;");
        wait_for_workers();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn punycode_names_stay_in_ascii_form() {
        let _serial = serial();
        let fixtures = Fixtures::new();
        let event = fixtures.resolve("xn--bcher-kva.example.test.", |q| {
            fixtures.reply(q).to_vec().ok()
        });
        assert_eq!(status(&event), "secure");
        let result = &event["result"];
        assert_eq!(result["canonical_name"], "xn--caf-dma.other.test.");
        assert_eq!(result["records"][0]["name"], "xn--caf-dma.other.test.");
        assert_eq!(result["aliases"][0]["name"], "xn--bcher-kva.example.test.");
        assert_eq!(result["aliases"][0]["data"], "xn--caf-dma.other.test.");
        wait_for_workers();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn dname_synthesized_cname_is_not_authenticated() {
        let _serial = serial();
        let fixtures = Fixtures::new();
        let event = fixtures.resolve("bob.redirect.example.test.", |q| {
            fixtures.reply(q).to_vec().ok()
        });
        assert_eq!(status(&event), "bogus");
        assert_eq!(event["result"]["records"], json!([]));
        wait_for_workers();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn records_outside_the_queried_owner_or_name_are_not_trusted() {
        let _serial = serial();
        let fixtures = Fixtures::new();
        for name in [
            "alice.sibling.test.",
            "alice.cousin.test.",
            "alice.orphan.test.",
            "wild-valid.example.test.",
            "expanded-alias.example.test.",
        ] {
            let event = fixtures.resolve(name, |q| fixtures.reply(q).to_vec().ok());
            assert_eq!(status(&event), "bogus", "{name}");
            assert_eq!(event["result"]["records"], json!([]));
            assert_eq!(event["result"]["aliases"], json!([]));
        }
        wait_for_workers();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn multi_record_rrsets_are_returned_in_full() {
        let _serial = serial();
        let fixtures = Fixtures::new();
        let event = fixtures.resolve("multi.example.test.", |q| fixtures.reply(q).to_vec().ok());
        assert_eq!(status(&event), "secure");
        let texts: Vec<String> = event["result"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let txt: Vec<u8> = serde_json::from_value(r["txt"].clone()).unwrap();
                String::from_utf8(txt).unwrap()
            })
            .collect();
        assert_eq!(
            texts,
            [
                "oa1:xmr part=one;",
                "oa1:xmr part=two;",
                "oa1:xmr part=three;"
            ]
        );
        wait_for_workers();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn unsupported_delegation_algorithms_are_insecure() {
        let _serial = serial();
        let fixtures = Fixtures::new();
        let event = fixtures.resolve("alice.legacy.test.", |q| fixtures.reply(q).to_vec().ok());
        assert_eq!(status(&event), "insecure");
        assert_eq!(event["result"]["records"], json!([]));
        wait_for_workers();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn aliases_ending_in_authenticated_nodata_report_no_records() {
        let _serial = serial();
        let fixtures = Fixtures::new();
        for (name, target) in [
            ("alias-empty.example.test.", "empty.other.test."),
            ("alias-nodata.example.test.", "empty.example.test."),
        ] {
            let event = fixtures.resolve(name, |q| fixtures.reply(q).to_vec().ok());
            assert_eq!(status(&event), "noRecords", "{name}");
            assert_eq!(event["result"]["canonical_name"], target);
            assert_eq!(event["result"]["aliases"].as_array().unwrap().len(), 1);
            assert_eq!(event["result"]["records"], json!([]));
        }
        wait_for_workers();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hostile_responses_fail_closed() {
        let _serial = serial();
        let fixtures = Fixtures::new();
        let target = |q: &Message| q.queries[0].query_type == RecordType::TXT;
        let inflate = |q: &Message, extra: &dyn Fn(&mut Message)| {
            let mut message = fixtures.reply(q);
            if target(q) {
                extra(&mut message);
            }
            message.to_vec().ok()
        };
        let many_records = |m: &mut Message| {
            let owner = m.answers[0].name.clone();
            m.additionals.extend((0..300).map(|i| {
                Record::from_rdata(
                    owner.clone(),
                    300,
                    RData::TXT(TXT::new(vec![format!("{i}")])),
                )
            }));
        };
        let many_signatures = |m: &mut Message| {
            let signature = m
                .answers
                .iter()
                .find(|r| r.record_type() == RecordType::RRSIG)
                .unwrap()
                .clone();
            m.answers.extend((0..16).map(|i| {
                let mut copy = signature.clone();
                if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &signature.data {
                    let input = SigInput {
                        key_tag: i,
                        ..sig.input().clone()
                    };
                    copy.data = RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(
                        input,
                        sig.sig().to_vec(),
                    )));
                }
                copy
            }));
        };
        for extra in [&many_records as &dyn Fn(&mut Message), &many_signatures] {
            let event = fixtures.resolve("alice.example.test.", |q| inflate(q, extra));
            assert_eq!(status(&event), "indeterminate");
            assert_eq!(event["result"]["records"], json!([]));
        }
        let event = fixtures.resolve("alice.example.test.", |q| {
            let mut bytes = fixtures.reply(q).to_vec().unwrap();
            if target(q) {
                bytes.resize(65536, 0);
            }
            Some(bytes)
        });
        assert_eq!(status(&event), "indeterminate");
        for name in [
            "tampered.example.test.",
            "wild.example.test.",
            "forged.example.test.",
        ] {
            let event = fixtures.resolve(name, |q| fixtures.reply(q).to_vec().ok());
            assert_ne!(status(&event), "secure", "{name}");
            assert_eq!(event["result"]["records"], json!([]));
        }
        wait_for_workers();
    }
}
