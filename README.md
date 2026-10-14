# dnssec_resolver

On-device DNSSEC validation over a caller-supplied `DohWireTransport`. The
validator is a native Rust crate built by the package's build hook; the Dart
side performs no networking of its own.

## Usage

```dart
import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:doh_transport/doh_transport_io.dart';

final transport = IoDohTransport();
try {
  final resolver = DnssecResolver(transport: transport);
  for (final record in await resolver.lookupTxt('example.com')) {
    print(record.text);
  }
} on DnssecException catch (error) {
  print('${error.code.name}: ${error.message}');
} finally {
  await transport.close();
}
```

`lookup` returns a `DnssecResult` with its `status` (`secure`, `insecure`,
`bogus`, `indeterminate`), records and CNAME aliases. `lookupTxt` and
`DnssecResult.secureTxt()` return TXT records from a `secure` answer and throw
`DnssecException` otherwise. Record types: A, CNAME, TXT and AAAA.

## Trust model

Every answer is validated locally from the trust anchors down to the queried
owner. The DoH endpoint is only a transport: it can withhold or delay answers
but cannot forge a secure one. Answers are scoped to the queried owner;
additional-section data is ignored and expanded records are rejected. RRSIGs
using SHA-1 based algorithms are ignored. The endpoint sees every query the
validator makes, from the root keys down, and, without a proxy, your address.
`DnssecResolver.validator` identifies this package to consumers that check a
`TxtAnswer.validator`, such as `openalias`.

## Configuration

- `endpoint`: an RFC 8484 URI, `https://dns.google/dns-query` by default.
- `timeout` 20 s (at most 2 minutes) for a whole lookup, including its
  sub-queries.
- `maxQueries` 64 (at most 128) per lookup.
- `trustAnchors`: DNSKEY records in zone presentation format; the IANA root
  keys by default.
- Proxy, fixed destination, connection reuse and transport deadlines belong to
  the transport; see `doh_transport`.

## Building

The build hook compiles `native/` with `cargo build --locked`. Building needs
rustup with the toolchain in `native/rust-toolchain.toml` and the Rust target
for each platform you build for. Dart SDK 3.10 or later.

## Development

`doh_transport` is not on pub.dev yet: clone it beside this repository and add
`pubspec_overrides.yaml`:

```yaml
dependency_overrides:
  doh_transport:
    path: ../doh_transport
```

`bash tool/check.sh` runs format, analyze, the cargo checks and the tests.
`tool/notices.py` regenerates `NOTICES` from the crate licenses.

## License

MIT; see `LICENSE`. `NOTICES` lists the licenses of the bundled Rust crates.
`test/support/LICENSE` covers the test support files.
