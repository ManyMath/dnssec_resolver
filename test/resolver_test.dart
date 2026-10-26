import 'dart:async';
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

  test('a slow transport is still observed', () async {
    final slow = FixtureTransport(
      fixtures,
      delay: const Duration(milliseconds: 120),
    );
    final result = await DnssecResolver(
      transport: slow,
      trustAnchors: fixtures.anchor,
    ).lookupTxt('alice.example.test');
    expect(result.single.text, 'oa1:xmr recipient_address=valid;');
    expect(slow.queries, isNotEmpty);
  });

  test('cancel stops further activity', () async {
    final slow = FixtureTransport(
      fixtures,
      delay: const Duration(milliseconds: 600),
    );
    final operation = DnssecResolver(
      transport: slow,
      trustAnchors: fixtures.anchor,
    ).startTxtLookup('alice.example.test');
    final outcome = expectLater(
      operation.result,
      throwsA(isA<DnssecCancelledException>()),
    );
    while (slow.queries.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 5));
    }
    operation.cancel();
    await outcome;
    final before = slow.queries.length;
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(slow.queries.length, before);
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

  test('rejects out-of-range configuration', () {
    for (final create in <void Function()>[
      () => DnssecResolver(transport: transport, timeout: Duration.zero),
      () => DnssecResolver(
        transport: transport,
        timeout: const Duration(minutes: 2, milliseconds: 1),
      ),
      () => DnssecResolver(transport: transport, maxQueries: 0),
      () => DnssecResolver(transport: transport, maxQueries: 129),
      () => DnssecResolver(transport: transport, trustAnchors: ' '),
      () => DnssecResolver(transport: transport, trustAnchors: 'a' * 60001),
    ]) {
      expect(create, throwsArgumentError);
    }
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
        throwsA(isA<DnssecInvalidNameException>()),
      );
      // Starting never throws for a bad name; the operation fails instead.
      await expectLater(
        resolver.startLookup(name).result,
        throwsA(isA<DnssecInvalidNameException>()),
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
        isA<DnssecValidationException>().having(
          (error) => error.status,
          'status',
          DnssecStatus.insecure,
        ),
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

  test('SHA-1 only delegations are bogus', () async {
    final result = await resolver.lookup('alice.sha1-ds.test');
    expect(result.status, DnssecStatus.bogus);
    expect(result.records, isEmpty);
  });

  test('mixed digest delegations stay secure', () async {
    final result = await resolver.lookup('alice.mixed-ds.test');
    expect(result.status, DnssecStatus.secure);
    expect(result.secureTxt().single.text, contains('valid'));
  });

  for (final (name, status) in [
    ('empty.unsigned.test', DnssecStatus.insecure),
    ('missing.unsigned.test', DnssecStatus.insecure),
    ('bare.unsigned.test', DnssecStatus.indeterminate),
  ]) {
    test('an unproven denial for $name is not a missing record', () async {
      final result = await resolver.lookup(name);
      expect(result.status, status);
      expect(result.records, isEmpty);
      await expectLater(
        resolver.lookupTxt(name),
        throwsA(
          isA<DnssecValidationException>().having(
            (error) => error.status,
            'status',
            status,
          ),
        ),
      );
    });
  }

  for (final name in ['alias-empty', 'alias-nodata']) {
    test('$name alias ending in authenticated NODATA has no records', () async {
      await expectLater(
        resolver.lookupTxt('$name.example.test'),
        throwsA(isA<DnssecNoRecordException>()),
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

  test('maps port failures and rejects an oversized response itself', () async {
    final failure = StateError('upstream failed');
    for (final port in [
      FixtureTransport(fixtures, failure: failure),
      FixtureTransport(fixtures, mutate: (_, _) => throw failure),
    ]) {
      await expectLater(
        DnssecResolver(
          transport: port,
          trustAnchors: fixtures.anchor,
        ).lookupTxt('alice.example.test'),
        throwsA(
          isA<DnssecTransportException>().having(
            (error) => error.cause,
            'cause',
            same(failure),
          ),
        ),
      );
    }
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
      throwsA(isA<DnssecResponseTooLargeException>()),
    );
  });

  test('cache Age is subtracted from validated TTLs', () async {
    final fresh = await resolver.lookupTxt('alice.example.test');
    transport = FixtureTransport(
      fixtures,
      age: const Duration(seconds: 100, milliseconds: 999),
    );
    resolver = DnssecResolver(
      transport: transport,
      trustAnchors: fixtures.anchor,
    );
    final aged = await resolver.lookupTxt('alice.example.test');
    expect(aged.single.ttl, fresh.single.ttl - 100);
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
    expect(() => result.records.single.txt!.add(0), throwsUnsupportedError);

    final looping = DnssecResult(
      question: result.question,
      recordType: result.recordType,
      canonicalName: result.canonicalName,
      status: result.status,
      records: result.records,
      aliases: [
        ...result.aliases,
        DnssecRecord(
          name: 'alias.example.test',
          type: 5,
          ttl: 1,
          data: 'alias.example.test.',
        ),
      ],
    );
    final withoutTxt = DnssecResult(
      question: result.question,
      recordType: result.recordType,
      canonicalName: result.canonicalName,
      status: result.status,
      records: [
        for (final record in result.records)
          DnssecRecord(
            name: record.name,
            type: record.type,
            ttl: record.ttl,
            data: record.data,
          ),
      ],
      aliases: result.aliases,
    );
    for (final malformed in [looping, withoutTxt]) {
      expect(
        malformed.secureTxt,
        throwsA(isA<DnssecMalformedResponseException>()),
      );
    }
  });

  test('secure TXT accessor rejects every non-secure status', () async {
    final secure = await resolver.lookup('alice.example.test');
    expect(secure.secureTxt().single.text, contains('valid'));
    for (final status in [
      DnssecStatus.insecure,
      DnssecStatus.bogus,
      DnssecStatus.indeterminate,
    ]) {
      final result = DnssecResult(
        question: secure.question,
        recordType: secure.recordType,
        canonicalName: secure.canonicalName,
        status: status,
        records: secure.records,
        aliases: secure.aliases,
      );
      expect(
        result.secureTxt,
        throwsA(
          isA<DnssecValidationException>().having(
            (error) => error.status,
            'status',
            status,
          ),
        ),
      );
    }
  });

  for (final entry in {
    'ambiguous': isA<DnssecAliasAmbiguousException>(),
    'chain0': isA<DnssecAliasTooLongException>(),
  }.entries) {
    test('rejects ${entry.key} CNAME chain', () async {
      await expectLater(
        resolver.lookupTxt('${entry.key}.example.test'),
        throwsA(entry.value),
      );
    });
  }

  for (final name in ['loop', 'one']) {
    test('rejects $name CNAME loop', () async {
      await expectLater(
        resolver.lookupTxt('$name.example.test'),
        throwsA(isA<DnssecAliasLoopException>()),
      );
    });
  }

  test('authenticated NODATA never supplies a recipient', () async {
    await expectLater(
      resolver.lookupTxt('empty.example.test'),
      throwsA(isA<DnssecNoRecordException>()),
    );
  });

  test('NSEC3 authenticated NODATA never supplies a recipient', () async {
    await expectLater(
      resolver.lookupTxt('nsec3.example.test'),
      throwsA(isA<DnssecNoRecordException>()),
    );
  });

  for (final name in ['missing.example.test', 'missing3.example.test']) {
    test('secure NXDOMAIN for $name never supplies a recipient', () async {
      await expectLater(
        resolver.lookupTxt(name),
        throwsA(isA<DnssecNoRecordException>()),
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
              ? isA<DnssecMalformedResponseException>()
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
            cancel
                ? isA<DnssecCancelledException>()
                : isA<DnssecTimeoutException>().having(
                    (e) => e.timeout,
                    'timeout',
                    const Duration(milliseconds: 300),
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

  test('exception leaves expose structured fields and readable types', () {
    final validation = DnssecValidationException(
      'not secure',
      status: DnssecStatus.bogus,
    );
    expect(validation, isA<DnssecException>());
    expect(validation.status, DnssecStatus.bogus);
    expect(
      validation.toString(),
      'DnssecValidationException(status: bogus): not secure',
    );
    expect(
      () => DnssecValidationException('secure', status: DnssecStatus.secure),
      throwsArgumentError,
    );

    final cause = StateError('socket');
    final stack = StackTrace.current;
    final transport = DnssecTransportException(
      'exchange failed',
      cause: cause,
      causeStackTrace: stack,
    );
    expect(transport.cause, same(cause));
    expect(transport.causeStackTrace, same(stack));
    expect(transport.toString(), 'DnssecTransportException: exchange failed');

    const timeout = DnssecTimeoutException(
      'deadline',
      timeout: Duration(seconds: 20),
    );
    expect(timeout.timeout, const Duration(seconds: 20));
    expect(
      timeout.toString(),
      'DnssecTimeoutException(timeout: 0:00:20.000000): deadline',
    );

    const leaves = <DnssecException>[
      DnssecAliasAmbiguousException('m', cause: 'payload'),
      DnssecAliasTooLongException('m', cause: 'payload'),
      DnssecAliasLoopException('m', cause: 'payload'),
      DnssecNoRecordException('m', cause: 'payload'),
      DnssecInvalidNameException('m', cause: 'payload'),
      DnssecResponseTooLargeException('m', cause: 'payload'),
      DnssecQuestionMismatchException('m', cause: 'payload'),
      DnssecQueryFailedException('m', cause: 'payload'),
      DnssecUnavailableException('m', cause: 'payload'),
      DnssecCancelledException('m', cause: 'payload'),
      DnssecMalformedResponseException('m', cause: 'payload'),
    ];
    for (final error in leaves) {
      expect(error.message, 'm');
      expect(error.cause, 'payload');
      expect(error.toString(), '${error.runtimeType}: m');
    }
    expect(leaves.map((e) => e.runtimeType).toSet(), hasLength(leaves.length));
  });

  test(
    'dropped ordinary and failed operations are immediately handled',
    () async {
      final uncaught = <Object>[];
      await runZonedGuarded(() async {
        DnssecOperation<void>(
          Future<void>.error(
            const DnssecTransportException('ordinary dropped'),
          ),
          () {},
        );
        DnssecOperation<void>.failed(const DnssecCancelledException('dropped'));
        await Future<void>.delayed(Duration.zero);
      }, (error, _) => uncaught.add(error));
      expect(uncaught, isEmpty);
    },
  );
}

class StalledTransport implements DnssecWireTransport {
  final started = Completer<void>();
  bool cancelled = false;
  @override
  DnssecOperation<DnssecWireResponse> startWire(
    List<int> query, {
    required int maxResponseBytes,
  }) {
    if (!started.isCompleted) started.complete();
    final result = Completer<DnssecWireResponse>();
    return DnssecOperation(result.future, () {
      cancelled = true;
      if (!result.isCompleted) {
        result.completeError(const DnssecCancelledException('cancelled'));
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
