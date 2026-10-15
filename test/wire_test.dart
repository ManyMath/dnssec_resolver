import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:dnssec_resolver/src/wire.dart';
import 'package:test/test.dart';

void main() {
  test('Age is applied once to non-OPT TTL and output is immutable', () {
    final query = _query();
    final response = _response(ttl: 300);
    final adjusted = validateAndAgeDnssecWireResponse(
      query,
      response,
      age: const Duration(seconds: 120, milliseconds: 999),
    );
    expect(_answerTtl(adjusted), 180);
    expect(_optTtl(adjusted), 0x00008000, reason: 'EDNS flags are not a TTL');
    expect(_answerTtl(response), 300, reason: 'input is not mutated');
    expect(() => adjusted.add(0), throwsUnsupportedError);
  });

  test('RFC 2181 high-bit TTL is zero before Age subtraction', () {
    final adjusted = validateAndAgeDnssecWireResponse(
      _query(),
      _response(ttl: 0x80000001),
      age: Duration.zero,
    );
    expect(_answerTtl(adjusted), 0);
  });

  test('rejects duplicate and nonzero-version OPT records', () {
    final duplicate = [..._response()]
      ..[11] = 2
      ..addAll(_opt());
    expect(
      () => validateAndAgeDnssecWireResponse(
        _query(),
        duplicate,
        age: Duration.zero,
      ),
      throwsA(isA<DnssecMalformedResponseException>()),
    );

    final nonzeroVersion = [..._response()];
    final opt = _optOffset(nonzeroVersion);
    nonzeroVersion[opt + 6] = 1;
    expect(
      () => validateAndAgeDnssecWireResponse(
        _query(),
        nonzeroVersion,
        age: Duration.zero,
      ),
      throwsA(isA<DnssecMalformedResponseException>()),
    );
  });

  test('rejects hostile compression and a different question', () {
    final loopingQuestion = [..._response()]
      ..[12] = 0xc0
      ..[13] = 0x0c;
    expect(
      () => validateAndAgeDnssecWireResponse(
        _query(),
        loopingQuestion,
        age: Duration.zero,
      ),
      throwsA(isA<DnssecMalformedResponseException>()),
    );

    final other = [..._response()]..[13] = 'b'.codeUnitAt(0);
    expect(
      () =>
          validateAndAgeDnssecWireResponse(_query(), other, age: Duration.zero),
      throwsA(isA<DnssecQuestionMismatchException>()),
    );
  });
}

List<int> _name() => [1, 0x61, 7, ...'example'.codeUnits, 0];

List<int> _question() => [..._name(), 0, 16, 0, 1];

List<int> _opt() => [0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0];

List<int> _query() => [
  0x12,
  0x34,
  0x01,
  0x00,
  0,
  1,
  0,
  0,
  0,
  0,
  0,
  1,
  ..._question(),
  ..._opt(),
];

List<int> _response({int ttl = 300}) => [
  0x12,
  0x34,
  0x81,
  0x80,
  0,
  1,
  0,
  1,
  0,
  0,
  0,
  1,
  ..._question(),
  0xc0,
  0x0c,
  0,
  16,
  0,
  1,
  ttl >> 24 & 0xff,
  ttl >> 16 & 0xff,
  ttl >> 8 & 0xff,
  ttl & 0xff,
  0,
  2,
  1,
  0x61,
  ..._opt(),
];

int _questionEnd(List<int> message) => 12 + _question().length;

int _answerTtl(List<int> message) {
  final offset = _questionEnd(message) + 2 + 4;
  return _u32(message, offset);
}

int _optOffset(List<int> message) => _questionEnd(message) + 2 + 10 + 2;

int _optTtl(List<int> message) => _u32(message, _optOffset(message) + 5);

int _u32(List<int> bytes, int offset) =>
    bytes[offset] << 24 |
    bytes[offset + 1] << 16 |
    bytes[offset + 2] << 8 |
    bytes[offset + 3];
