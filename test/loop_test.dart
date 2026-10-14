import 'dart:async';

import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:doh_transport/doh_transport_io.dart';
import 'package:doh_transport/testing.dart';
import 'package:test/test.dart';

import 'support/fixture_transport.dart';

const _ecs = [0, 8, 0, 4, 0, 1, 0, 0];

typedef _ReplyMutation =
    List<int> Function(int request, List<int> query, List<int> reply);

final class _Loop {
  final FakeDohHttpClient fake;
  final IoDohTransport transport;
  final DnssecResolver resolver;

  const _Loop(this.fake, this.transport, this.resolver);
}

bool _contains(List<int> bytes, List<int> sequence) {
  for (var i = 0; i + sequence.length <= bytes.length; i++) {
    var matches = true;
    for (var j = 0; j < sequence.length; j++) {
      if (bytes[i + j] != sequence[j]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

Future<void> _until(bool Function() condition) async {
  for (var i = 0; i < 200 && !condition(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  expect(condition(), isTrue);
}

void main() {
  final fixtures = Fixtures();
  final endpoint = Uri.https('resolver.example', '/dns-query');

  _Loop loop({
    List<FakeDohHttpScript> scripts = const [],
    _ReplyMutation? mutate,
    Duration resolverTimeout = const Duration(seconds: 2),
    Duration requestTimeout = const Duration(seconds: 1),
    int maxQueries = 64,
    int maxConcurrentRequests = 8,
  }) {
    var request = 0;
    final fake = FakeDohHttpClient(
      scripts: scripts,
      reply: (_, query) {
        final reply = fixtures.reply(query);
        return mutate == null ? reply : mutate(request++, query, reply);
      },
    );
    final transport = IoDohTransport(
      httpClientFactory: fake.create,
      requestTimeout: requestTimeout,
      maxConcurrentRequests: maxConcurrentRequests,
      reuseConnections: true,
    );
    addTearDown(transport.close);
    return _Loop(
      fake,
      transport,
      DnssecResolver(
        transport: transport,
        endpoint: endpoint,
        timeout: resolverTimeout,
        maxQueries: maxQueries,
        trustAnchors: fixtures.anchor,
      ),
    );
  }

  test(
    'secure chain uses padded privacy-preserving queries and one client',
    () async {
      final subject = loop();
      final records = await subject.resolver.lookupTxt('alice.example.test');
      expect(records.single.text, contains('valid'));
      expect(subject.fake.createdClients, 1);
      for (final request in subject.fake.requests) {
        final query = request.body;
        expect(query.length % 128, 0);
        expect(query[2] & 1, 1, reason: 'RD required');
        expect(query[3] & 0x10, 0x10, reason: 'CD required');
        expect(query[3] & 0x20, 0, reason: 'AD must be clear');
        final questionEnd = Fixtures.question(query).$3;
        expect(query[questionEnd + 7] & 0x80, 0x80, reason: 'DO required');
        expect(
          _contains(query, _ecs),
          isTrue,
          reason: 'zero-length ECS required',
        );
        expect(_contains(query, [0, 12]), isTrue, reason: 'padding required');
      }
    },
  );

  test('secure CNAME crossing zones is validated', () async {
    final result = await loop().resolver.lookup('alias.example.test');
    expect(result.status, DnssecStatus.secure);
    expect(result.canonicalName, 'bob.other.test');
    expect(result.secureTxt().single.text, contains('valid'));
  });

  for (final name in [
    'unsigned.test',
    'unsigned3.test',
    'unsigned-optout.test',
  ]) {
    test('$name is an insecure delegation', () async {
      final result = await loop().resolver.lookup(name);
      expect(result.status, DnssecStatus.insecure);
      expect(result.records, isEmpty);
    });
  }

  for (final name in [
    'tampered.example.test',
    'expired.example.test',
    'future.example.test',
    'alice.bad-ds.test',
  ]) {
    test('$name is never accepted as secure', () async {
      final result = await loop().resolver.lookup(name);
      expect(result.status, isNot(DnssecStatus.secure));
      expect(result.records, isEmpty);
    });
  }

  for (final name in [
    'empty.example.test',
    'nsec3.example.test',
    'missing.example.test',
    'missing3.example.test',
  ]) {
    test('$name is a secure negative answer', () async {
      await expectLater(
        loop().resolver.lookupTxt(name),
        throwsA(
          isA<DnssecException>().having(
            (error) => error.code,
            'code',
            DnssecError.noRecords,
          ),
        ),
      );
    });
  }

  test(
    'transport rejects a truncated reply before native validation',
    () async {
      final subject = loop(mutate: (_, _, reply) => reply..[2] |= 2);
      await expectLater(
        subject.resolver.lookupTxt('alice.example.test'),
        throwsA(isA<DnsMalformedResponseException>()),
      );
    },
  );

  test('transport rejects oversized declared and chunked bodies', () async {
    final declared = loop(
      scripts: const [FakeDohHttpScript(declaredContentLength: 65536)],
    );
    await expectLater(
      declared.resolver.lookupTxt('alice.example.test'),
      throwsA(isA<DnsResponseTooLargeException>()),
    );

    final chunked = loop(
      scripts: const [
        FakeDohHttpScript(chunkSizes: [32768, 32768]),
      ],
      mutate: (_, _, _) => List<int>.filled(65536, 0),
    );
    await expectLater(
      chunked.resolver.lookupTxt('alice.example.test'),
      throwsA(isA<DnsResponseTooLargeException>()),
    );
  });

  test('transport preserves an HTTP 500 status', () async {
    final subject = loop(scripts: const [FakeDohHttpScript(statusCode: 500)]);
    await expectLater(
      subject.resolver.lookupTxt('alice.example.test'),
      throwsA(
        isA<DnsTransportException>().having(
          (error) => error.httpStatus,
          'httpStatus',
          500,
        ),
      ),
    );
  });

  test('HTTP Age reduces the validated TXT TTL', () async {
    final subject = loop(
      scripts: List.filled(64, const FakeDohHttpScript(age: '120')),
    );
    final result = await subject.resolver.lookupTxt('alice.example.test');
    expect(result.single.ttl, 180);
  });

  test(
    'resolver deadline wins over the transport deadline and aborts',
    () async {
      final subject = loop(
        scripts: const [FakeDohHttpScript(hang: true)],
        resolverTimeout: const Duration(milliseconds: 30),
        requestTimeout: const Duration(seconds: 1),
      );
      await expectLater(
        subject.resolver.lookupTxt('alice.example.test'),
        throwsA(
          isA<DnssecException>().having(
            (error) => error.code,
            'code',
            DnssecError.timedOut,
          ),
        ),
      );
      expect(subject.fake.aborts, greaterThan(0));
    },
  );

  test('transport deadline passes through as DnsTimeoutException', () async {
    final subject = loop(
      scripts: const [FakeDohHttpScript(hang: true)],
      resolverTimeout: const Duration(seconds: 1),
      requestTimeout: const Duration(milliseconds: 20),
    );
    await expectLater(
      subject.resolver.lookupTxt('alice.example.test'),
      throwsA(isA<DnsTimeoutException>()),
    );
    expect(subject.fake.aborts, greaterThan(0));
  });

  test('cancellation stops the real transport operation', () async {
    final subject = loop(scripts: const [FakeDohHttpScript(hang: true)]);
    final operation = subject.resolver.startTxtLookup('alice.example.test');
    final failed = expectLater(
      operation.result,
      throwsA(
        isA<DnssecException>().having(
          (error) => error.code,
          'code',
          DnssecError.cancelled,
        ),
      ),
    );
    await _until(() => subject.fake.requests.isNotEmpty);
    operation.cancel();
    await failed;
    expect(subject.fake.aborts, greaterThan(0));
    operation.cancel();
  });

  test('maxQueries bounds the real transport loop', () async {
    final subject = loop(maxQueries: 2);
    await expectLater(
      subject.resolver.lookupTxt('alice.example.test'),
      throwsA(isA<DnssecException>()),
    );
    expect(subject.fake.requests.length, lessThanOrEqualTo(2));
  });

  test('the engine can overlap exchanges up to the transport limit', () async {
    final subject = loop(
      scripts: List.filled(
        64,
        const FakeDohHttpScript(delay: Duration(milliseconds: 20)),
      ),
      maxConcurrentRequests: 8,
    );
    final results = await Future.wait([
      subject.resolver.lookupTxt('alice.example.test'),
      subject.resolver.lookupTxt('bob.other.test'),
      subject.resolver.lookupTxt('alias.example.test'),
    ]);
    expect(
      results.every((records) => records.single.text.contains('valid')),
      isTrue,
    );
    expect(subject.fake.maxActiveRequests, greaterThan(1));
    expect(subject.fake.maxActiveRequests, lessThanOrEqualTo(8));
  });
}
