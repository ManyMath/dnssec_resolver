# dnssec_resolver

On-device DNSSEC validation over a caller-supplied `DnssecWireTransport`. The
validator is a native Rust crate built by the package's build hook; the Dart
side performs no networking of its own.

## Usage

```dart
import 'package:dnssec_resolver/dnssec_resolver.dart';

final resolver = DnssecResolver(transport: MyDnssecWireTransport());
try {
  for (final record in await resolver.lookupTxt('example.com')) {
    print(record.text);
  }
} on DnssecException catch (error) {
  print(error);
}
```

The transport sends each wire query upstream, for example over DNS over HTTPS,
reads at most `maxResponseBytes` and returns the DNS message with its cache
`age`, which is subtracted from every TTL.

`lookup` returns a `DnssecResult` with its `status` (`secure`, `insecure`,
`bogus`, `indeterminate`), records and CNAME aliases. `lookupTxt` and
`DnssecResult.secureTxt()` return TXT records from a `secure` answer and throw
a `DnssecException` otherwise. `lookup` and `lookupTxt` report a secure NODATA
or NXDOMAIN proof as `DnssecNoRecordException`. `startLookup` and
`startTxtLookup` return a cancellable `DnssecOperation` whose `result` carries
every failure, including an invalid name; an unsupported record type throws
`ArgumentError`. Record types: A, CNAME, TXT and AAAA.

## Trust model

Every answer is validated locally from the trust anchors down to the queried
owner. The transport and the upstream resolver can withhold or delay answers
but cannot forge a secure one. Because the caller supplies the transport, each
wire response is matched against its query and bounded again here, so callers
need not repeat those checks; nothing a sibling package or private seam already
guarantees is checked twice. Answers are scoped to the queried owner;
additional-section data is ignored and expanded records are rejected. The
upstream resolver sees every query the validator makes, from the root keys
down, and, without a proxy, your address. Consumers must use `lookupTxt` or
call `secureTxt()` before accepting TXT data. `secureTxt()` throws
`DnssecValidationException` for insecure, bogus or indeterminate results and
`DnssecMalformedResponseException` for malformed ones.

## Configuration

- `timeout` 20 s (at most 2 minutes) for a whole lookup, including its
  sub-queries.
- `maxQueries` 64 (at most 128) per lookup.
- `trustAnchors`: DNSKEY records in zone presentation format (non-empty, at
  most 60000 bytes); the IANA root keys by default.
- Endpoint, proxy, connection reuse and transport deadlines belong to the
  caller-supplied transport.

## Transport contract

`DnssecWireTransport.startWire(query, maxResponseBytes: n)` returns a
`DnssecOperation<DnssecWireResponse>` (DNS message, cache `age`). It must not
throw: failures complete the operation with a `DnssecException` of the
implementation's choosing; any other error is wrapped as
`DnssecTransportException` with the original in `cause`. `cancel` is
idempotent and is also called after the result completes. The transport stops
reading after `maxResponseBytes`; the resolver re-checks the size and matches
the response's ID, opcode and question against the query.

## Building

The build hook compiles `native/` with `cargo build --locked`. Building needs
rustup with the toolchain in `native/rust-toolchain.toml` and the Rust target
for each platform you build for. Dart SDK 3.10 or later.

## License

MIT; see `LICENSE`. `NOTICES` lists the licenses of the bundled Rust crates.
`test/support/LICENSE` in the repository covers the test support files.
