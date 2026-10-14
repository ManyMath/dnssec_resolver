## 0.0.1

- Local DNSSEC validation over `doh_transport` with cancellation, bounded queries, secure-only TXT access, validated CNAME chains and Age-adjusted TTLs.
- Answers are scoped to the queried owner; additional-section data is ignored and expanded records are rejected.
- Aliases ending in an authenticated NODATA answer report `noRecords`.
- Lookups are limited to A, CNAME, TXT and AAAA.
- The native ABI version is checked on the first lookup.
- Identical in-flight questions within one lookup share one exchange.
- RRSIGs using SHA-1 based algorithms are ignored.
