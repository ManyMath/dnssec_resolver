import 'dart:convert';
import 'dart:io';
import 'package:dnssec_resolver/dnssec_resolver.dart';

class Fixtures {
  final Map<String, dynamic> _json =
      jsonDecode(File('test/support/zones.json').readAsStringSync())
          as Map<String, dynamic>;
  String get anchor => _json['anchor'] as String;

  static (String, int, int) question(List<int> wire) {
    var offset = 12;
    final labels = <String>[];
    while (wire[offset] != 0) {
      final length = wire[offset++];
      labels.add(ascii.decode(wire.sublist(offset, offset + length)));
      offset += length;
    }
    offset++;
    return (
      '${labels.join('.')}.',
      wire[offset] * 256 + wire[offset + 1],
      offset + 4,
    );
  }

  List<int> reply(List<int> query) {
    final (name, type, end) = question(query);
    final encoded = (_json['messages'] as Map)['$name:$type'] as String?;
    var response = encoded == null
        ? <int>[
            0,
            0,
            0x81,
            0x80,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            ...query.sublist(12, end),
          ]
        : base64Decode(encoded).toList();
    if (encoded != null) {
      final responseQuestionEnd = question(response).$3;
      response = [
        ...response.sublist(0, 12),
        ...query.sublist(12, end),
        ...response.sublist(responseQuestionEnd),
      ];
    }
    response[0] = query[0];
    response[1] = query[1];
    return response;
  }
}

class FixtureTransport implements DnssecWireTransport {
  final Fixtures fixtures;
  final List<List<int>> queries = [];
  final List<int> Function(List<int> query, List<int> reply)? mutate;
  final Duration age;
  final Object? failure;
  final Duration? delay;
  int cancellations = 0;
  FixtureTransport(
    this.fixtures, {
    this.mutate,
    this.age = Duration.zero,
    this.failure,
    this.delay,
  });

  @override
  DnssecOperation<DnssecWireResponse> startWire(
    List<int> query, {
    required int maxResponseBytes,
  }) {
    queries.add(query);
    final reply = fixtures.reply(query);
    Future<DnssecWireResponse> respond() => failure == null
        ? Future.value(
            DnssecWireResponse(
              mutate == null ? reply : mutate!(query, reply),
              age: age,
            ),
          )
        : Future.error(failure!);
    return DnssecOperation(
      delay == null ? respond() : Future.delayed(delay!, respond),
      () => cancellations++,
    );
  }
}
