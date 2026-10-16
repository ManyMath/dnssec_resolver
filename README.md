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
a `DnssecException` otherwise. `startLookup` and `startTxtLookup` return a
cancellable `DnssecOperation` whose `result` carries every failure, including
an invalid name. Record types: A, CNAME, TXT and AAAA.

## Trust model

Every answer is validated locally from the trust anchors down to the queried
owner. The transport and the upstream resolver can withhold or delay answers
but cannot forge a secure one. Answers are scoped to the queried owner;
additional-section data is ignored and expanded records are rejected. RRSIGs
using SHA-1 based algorithms are ignored. The upstream resolver sees every
query the validator makes, from the root keys down, and, without a proxy, your
address. Consumers must use `lookupTxt` or call `secureTxt()` before accepting
TXT data. `secureTxt()` throws `DnssecValidationException` for insecure, bogus
or indeterminate results and `DnssecMalformedResponseException` for malformed
ones.

## Configuration

- `timeout` 20 s (at most 2 minutes) for a whole lookup, including its
  sub-queries.
- `maxQueries` 64 (at most 128) per lookup.
- `trustAnchors`: DNSKEY records in zone presentation format; the IANA root
  keys by default.
- Endpoint, proxy, connection reuse and transport deadlines belong to the
  caller-supplied transport.

## Building

The build hook compiles `native/` with `cargo build --locked`. Building needs
rustup with the toolchain in `native/rust-toolchain.toml` and the Rust target
for each platform you build for. Dart SDK 3.10 or later.

## Development

`dart tool/check.dart` runs format, analyze, the cargo checks, the tests and a
publish dry run.
`tool/notices.py` regenerates `NOTICES` from the crate licenses.

## License

MIT; see `LICENSE`. `NOTICES` lists the licenses of the bundled Rust crates.
`test/support/LICENSE` covers the test support files.
