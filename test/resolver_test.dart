import 'dart:async';
import 'package:doh_transport/doh_transport.dart';
import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:test/test.dart';

import 'support/fixture_transport.dart';

const _suppressedClientSubnet = [0, 8, 0, 4, 0, 1, 0, 0];

void main() {
  final fixtures = Fixtures();
  late FixtureTransport transport;
  late DnssecResolver resolver;
  setUp(() {
    transport = FixtureTransport(fixtures);
    resolver = DnssecResolver(
      transport: transport,
      trustAnchors: fixtures.anchor,
    );
  });

  test('validates TXT through root, parent DS, and zone DNSKEY', () async {
    final result = await resolver.lookupTxt('ALICE.EXAMPLE.TEST.');
    expect(result.single.text, 'oa1:xmr recipient_address=valid;');
    expect(result.single.ttl, lessThanOrEqualTo(300));
    final queries = transport.queries.map(Fixtures.question).toList();
    expect(
      queries.map((q) => (q.$1, q.$2)),
      containsAll([
        ('.', 48),
        ('test.', 43),
        ('test.', 48),
        ('example.test.', 43),
        ('example.test.', 48),
      ]),
    );
    for (final query in transport.queries) {
      expect(query[3] & 0x10, 0x10, reason: 'CD must reach the upstream');
      expect(query[3] & 0x20, 0);
      expect(query[2] & 1, 1);
      final end = Fixtures.question(query).$3;
      expect(query[end + 7] & 0x80, 0x80, reason: 'EDNS DO required');
      expect(
        query.sublist(query.length - 8),
        _suppressedClientSubnet,
        reason: 'ECS must suppress client subnet disclosure',
      );
    }
  });

  test('secure CNAME crossing zones validates both delegations', () async {
    final result = await resolver.lookup('alias.example.test');
    expect(result.canonicalName, 'bob.other.test');
    expect(result.aliases.single.name, 'alias.example.test');
    expect(result.secureTxt().single.text, contains('valid'));
    expect(
      transport.queries.map(Fixtures.question).map((q) => (q.$1, q.$2)),
      contains(('other.test.', 43)),
    );
  });

  test('punycode names resolve in A-label form', () async {
    final result = await resolver.lookup('xn--bcher-kva.example.test');
    expect(result.canonicalName, 'xn--caf-dma.other.test');
    expect(result.records.single.name, 'xn--caf-dma.other.test');
    expect(result.aliases.single.name, 'xn--bcher-kva.example.test');
    expect(result.aliases.single.data, 'xn--caf-dma.other.test.');
  });

  for (final valid in [true, false]) {
    test(
      'expanded CNAME records are not accepted (valid denial: $valid)',
      () async {
        final name = valid ? 'alias-wild-valid' : 'alias-wild-missing';
        final target = valid ? 'wild-valid' : 'wild';
        final result = await resolver.lookup('$name.example.test');
        if (result.aliases.isNotEmpty) {
          expect(
            transport.queries.map(Fixtures.question).map((q) => (q.$1, q.$2)),
            contains(('$target.other.test.', 16)),
          );
        }
        expect(result.status, DnssecStatus.bogus);
        expect(result.records, isEmpty);
        expect(result.secureTxt, throwsA(isA<DnssecException>()));
      },
    );
  }

  for (final name in ['tampered', 'expired', 'future', 'forged', 'wild']) {
    test('rejects $name TXT even when upstream sets AD', () async {
      final result = await resolver.lookup('$name.example.test');
      expect(result.status, isNot(DnssecStatus.secure));
      expect(result.records, isEmpty);
      expect(result.secureTxt, throwsA(isA<DnssecException>()));
    });
  }

  test('DNAME-synthesized CNAME is never authenticated', () async {
    final result = await resolver.lookup('bob.redirect.example.test');
    expect(result.status, DnssecStatus.bogus);
    expect(result.records, isEmpty);
    expect(result.aliases, isEmpty);
    expect(
      transport.queries.map(Fixtures.question).map((q) => (q.$1, q.$2)),
      isNot(contains(('bob.other.test.', 16))),
    );
  });

  test('rejects unsupported record types and invalid names', () async {
    for (final type in [0, 2, 41, 99, 128, 250, 255, 256]) {
      expect(
        () => resolver.startLookup('alice.example.test', recordType: type),
        throwsArgumentError,
      );
      await expectLater(
        resolver.lookup('alice.example.test', recordType: type),
        throwsArgumentError,
      );
    }
    for (final name in ['', 'a..test', 'a\\.b.test', '*.example.test']) {
      await expectLater(
        resolver.lookupTxt(name),
        throwsA(
          isA<DnssecException>().having(
            (e) => e.code,
            'code',
            DnssecError.invalidName,
          ),
        ),
      );
    }
    expect(transport.queries, isEmpty);
  });

  test('unsigned delegation is distinguished from bogus signatures', () async {
    final result = await resolver.lookup('unsigned.test');
    expect(result.status, DnssecStatus.insecure);
    expect(
      result.secureTxt,
      throwsA(
        isA<DnssecException>()
            .having((error) => error.code, 'code', DnssecError.insecure)
            .having((error) => error.status, 'status', DnssecStatus.insecure),
      ),
    );
    final bogus = await resolver.lookup('tampered.example.test');
    expect(bogus.status, DnssecStatus.bogus);
  });

  test('NSEC3 opt-out permits only insecure delegation', () async {
    final result = await resolver.lookup('unsigned-optout.test');
    expect(result.status, DnssecStatus.insecure);
    expect(result.records, isEmpty);
    expect(result.secureTxt, throwsA(isA<DnssecException>()));
    final withoutOptOut = await resolver.lookup('unsigned-no-optout.test');
    expect(withoutOptOut.status, DnssecStatus.bogus);
    expect(withoutOptOut.records, isEmpty);
  });

  test('NSEC3 proves an unsigned delegation', () async {
    final result = await resolver.lookup('unsigned3.test');
    expect(result.status, DnssecStatus.insecure);
  });

  test('expanded TXT records are not accepted even with a denial', () async {
    final result = await resolver.lookup('wild-valid.example.test');
    expect(result.status, DnssecStatus.bogus);
    expect(result.records, isEmpty);
    expect(result.secureTxt, throwsA(isA<DnssecException>()));
  });

  for (final name in ['sibling', 'cousin', 'orphan']) {
    test('DS records owned by another name do not validate $name', () async {
      final result = await resolver.lookup('alice.$name.test');
      expect(result.status, DnssecStatus.bogus);
      expect(result.records, isEmpty);
      expect(result.secureTxt, throwsA(isA<DnssecException>()));
    });
  }

  test('a multi-record TXT RRset is returned in full', () async {
    final result = await resolver.lookupTxt('multi.example.test');
    expect(result.map((r) => r.text), [
      'oa1:xmr part=one;',
      'oa1:xmr part=two;',
      'oa1:xmr part=three;',
    ]);
  });

  test('unsupported delegation algorithms are insecure', () async {
    final result = await resolver.lookup('alice.legacy.test');
    expect(result.status, DnssecStatus.insecure);
    expect(result.records, isEmpty);
  });

  for (final name in ['alias-empty', 'alias-nodata']) {
    test('$name alias ending in authenticated NODATA has no records', () async {
      await expectLater(
        resolver.lookupTxt('$name.example.test'),
        throwsA(
          isA<DnssecException>().having(
            (e) => e.code,
            'code',
            DnssecError.noRecords,
          ),
        ),
      );
    });
  }

  test('rejects a signed DS referring to the wrong child key', () async {
    await expectLater(
      resolver.lookupTxt('alice.bad-ds.test'),
      throwsA(isA<DnssecException>()),
    );
  });

  test('high-bit TTLs are zeroed before validation', () async {
    transport = FixtureTransport(
      fixtures,
      mutate: (_, reply) => _withHighBitTtls(reply),
    );
    resolver = DnssecResolver(
      transport: transport,
      trustAnchors: fixtures.anchor,
    );
    final result = await resolver.lookupTxt('alice.example.test');
    expect(result.single.ttl, 0);
  });

  test('rejects a non-200 or oversized transport response itself', () async {
    transport = FixtureTransport(fixtures, statusCode: 500);
    resolver = DnssecResolver(
      transport: transport,
      trustAnchors: fixtures.anchor,
    );
    await expectLater(
      resolver.lookupTxt('alice.example.test'),
      throwsA(
        isA<DnsTransportException>().having(
          (error) => error.httpStatus,
          'httpStatus',
          500,
        ),
      ),
    );
    transport = FixtureTransport(
      fixtures,
      mutate: (_, _) => List<int>.filled(65536, 0),
    );
    resolver = DnssecResolver(
      transport: transport,
      trustAnchors: fixtures.anchor,
    );
    await expectLater(
      resolver.lookupTxt('alice.example.test'),
      throwsA(isA<DnsResponseTooLargeException>()),
    );
  });

  test('upstream TTL cannot exceed the signed TTL', () async {
    final result = await resolver.lookupTxt('ttl.example.test');
    expect(result.single.ttl, lessThanOrEqualTo(300));
  });

  test('secure TXT accessor snapshots and validates native evidence', () async {
    final result = await resolver.lookup('alias.example.test');
    final records = result.secureTxt();
    expect(records.single.text, contains('valid'));
    expect(() => records.add(records.single), throwsUnsupportedError);
    expect(() => result.records.clear(), throwsUnsupportedError);

    final malformed = DnssecResult(
      question: result.question,
      recordType: result.recordType,
      canonicalName: result.canonicalName,
      resolver: result.resolver,
      status: result.status,
      records: result.records,
      aliases: [
        ...result.aliases,
        const DnsRecord(
          name: 'alias.example.test',
          type: 5,
          ttl: 1,
          data: 'alias.example.test.',
        ),
      ],
      txtRecords: records,
    );
    expect(
      malformed.secureTxt,
      throwsA(
        isA<DnssecException>().having(
          (error) => error.code,
          'code',
          DnssecError.malformedResponse,
        ),
      ),
    );
  });

  for (final entry in {
    'ambiguous': DnssecError.aliasAmbiguous,
    'chain0': DnssecError.aliasTooLong,
  }.entries) {
    test('rejects ${entry.key} CNAME chain', () async {
      await expectLater(
        resolver.lookupTxt('${entry.key}.example.test'),
        throwsA(
          isA<DnssecException>().having((e) => e.code, 'code', entry.value),
        ),
      );
    });
  }

  for (final name in ['loop', 'one']) {
    test('rejects $name CNAME loop', () async {
      await expectLater(
        resolver.lookupTxt('$name.example.test'),
        throwsA(
          isA<DnssecException>().having(
            (e) => e.code,
            'code',
            DnssecError.aliasLoop,
          ),
        ),
      );
    });
  }

  test('authenticated NODATA never supplies a recipient', () async {
    await expectLater(
      resolver.lookupTxt('empty.example.test'),
      throwsA(
        isA<DnssecException>().having(
          (e) => e.code,
          'code',
          DnssecError.noRecords,
        ),
      ),
    );
  });

  test('NSEC3 authenticated NODATA never supplies a recipient', () async {
    await expectLater(
      resolver.lookupTxt('nsec3.example.test'),
      throwsA(
        isA<DnssecException>().having(
          (e) => e.code,
          'code',
          DnssecError.noRecords,
        ),
      ),
    );
  });

  for (final name in ['missing.example.test', 'missing3.example.test']) {
    test('secure NXDOMAIN for $name never supplies a recipient', () async {
      await expectLater(
        resolver.lookupTxt(name),
        throwsA(
          isA<DnssecException>().having(
            (e) => e.code,
            'code',
            DnssecError.noRecords,
          ),
        ),
      );
    });
  }

  test('valid signatures are accepted with AD cleared', () async {
    final transport = FixtureTransport(
      fixtures,
      mutate: (_, response) {
        response[3] &= ~0x20;
        return response;
      },
    );
    final result = await DnssecResolver(
      transport: transport,
      trustAnchors: fixtures.anchor,
    ).lookupTxt('alice.example.test');
    expect(result.single.text, contains('valid'));
  });

  for (final mutation in ['id', 'question', 'truncated', 'query', 'short']) {
    test('rejects malformed $mutation response', () async {
      final transport = FixtureTransport(
        fixtures,
        mutate: (_, reply) {
          switch (mutation) {
            case 'id':
              reply[1] ^= 1;
            case 'question':
              reply[13] ^= 1;
            case 'truncated':
              reply[2] |= 2;
            case 'query':
              reply[2] &= 0x7f;
            case 'short':
              return [0];
          }
          return reply;
        },
      );
      await expectLater(
        DnssecResolver(
          transport: transport,
          trustAnchors: fixtures.anchor,
        ).lookupTxt('alice.example.test'),
        // An unparseable body fails TTL adjustment before the engine sees it.
        throwsA(
          mutation == 'short'
              ? isA<DnsMalformedResponseException>()
              : isA<DnssecException>(),
        ),
      );
    });
  }

  test('missing or untrusted chain cannot be rescued by AD', () async {
    await expectLater(
      DnssecResolver(transport: transport).lookupTxt('alice.example.test'),
      throwsA(isA<DnssecException>()),
    );
  });

  test('query budget bounds chain expansion', () async {
    await expectLater(
      DnssecResolver(
        transport: transport,
        trustAnchors: fixtures.anchor,
        maxQueries: 2,
      ).lookupTxt('alice.example.test'),
      throwsA(isA<DnssecException>()),
    );
    expect(transport.queries.length, lessThanOrEqualTo(2));
  });

  for (final cancel in [false, true]) {
    test(
      '${cancel ? 'cancellation' : 'deadline'} stops pending transport',
      () async {
        final stalled = StalledTransport();
        final operation = DnssecResolver(
          transport: stalled,
          timeout: const Duration(milliseconds: 300),
        ).startTxtLookup('alice.example.test');
        final failed = expectLater(
          operation.result,
          throwsA(
            isA<DnssecException>().having(
              (e) => e.code,
              'code',
              cancel ? DnssecError.cancelled : DnssecError.timedOut,
            ),
          ),
        );
        await stalled.started.future;
        if (cancel) operation.cancel();
        await failed;
        expect(stalled.cancelled, isTrue);
        operation.cancel();
      },
    );
  }

  test(
    'independent lookups cannot share cancellation or validation state',
    () async {
      final stalled = StalledTransport();
      final first = DnssecResolver(
        transport: stalled,
      ).startTxtLookup('alice.example.test');
      final failed = expectLater(first.result, throwsA(isA<DnssecException>()));
      await stalled.started.future;
      first.cancel();
      final valid = await resolver.lookupTxt('alice.example.test');
      await failed;
      expect(valid.single.text, contains('valid'));
    },
  );
}

class StalledTransport implements DohWireTransport {
  final started = Completer<void>();
  bool cancelled = false;
  @override
  DnsOperation<DohHttpResponse> startWire(
    Uri endpoint,
    List<int> query, {
    required int maxResponseBytes,
    bool preserveMessage = false,
  }) {
    if (!started.isCompleted) started.complete();
    final result = Completer<DohHttpResponse>();
    return DnsOperation(result.future, () {
      cancelled = true;
      if (!result.isCompleted) {
        result.completeError(
          const DnssecException(DnssecError.cancelled, 'cancelled'),
        );
      }
    });
  }
}

/// Sets every non-OPT record TTL in a wire [message] to 0x80000000.
List<int> _withHighBitTtls(List<int> message) {
  final out = [...message];
  int skipName(int at) {
    while (true) {
      final length = out[at];
      if (length == 0) return at + 1;
      if (length & 0xc0 == 0xc0) return at + 2;
      at += 1 + length;
    }
  }

  int u16(int at) => out[at] << 8 | out[at + 1];
  var at = 12;
  for (var i = 0; i < u16(4); i++) {
    at = skipName(at) + 4;
  }
  for (var i = 0; i < u16(6) + u16(8) + u16(10); i++) {
    at = skipName(at);
    if (u16(at) != 41) out.setRange(at + 4, at + 8, [0x80, 0, 0, 0]);
    at += 10 + u16(at + 8);
  }
  return out;
}
