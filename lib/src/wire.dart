import 'dart:typed_data';

import 'dns.dart';

const _malformed = DnssecMalformedResponseException(
  'Malformed DNS wire message',
);

List<int> validateAndAgeDnssecWireResponse(
  List<int> query,
  List<int> response, {
  required Duration age,
}) {
  if (age < Duration.zero) throw ArgumentError.value(age, 'age');
  final sent = _WireMessage.parse(query, query: true);
  final reply = _WireMessage.parse(response, query: false);
  if (!reply.isResponse) throw _malformed;
  if (reply.flags & 0x0200 != 0) {
    throw const DnssecMalformedResponseException('Truncated DNS wire response');
  }
  if (reply.id != sent.id ||
      reply.opcode != sent.opcode ||
      reply.questions.length != 1 ||
      !reply.questions.single.matches(sent.questions.single)) {
    throw const DnssecQuestionMismatchException(
      'DNS wire response does not match query',
    );
  }
  final adjusted = Uint8List.fromList(response);
  for (final offset in reply.ttlOffsets) {
    final ttl = _u16(response, offset) << 16 | _u16(response, offset + 2);
    final effective = effectiveDnssecTtl(ttl, age: age);
    adjusted
      ..[offset] = effective >> 24
      ..[offset + 1] = effective >> 16 & 0xff
      ..[offset + 2] = effective >> 8 & 0xff
      ..[offset + 3] = effective & 0xff;
  }
  return List<int>.unmodifiable(adjusted);
}

int _u16(List<int> data, int offset) => data[offset] << 8 | data[offset + 1];

final class _Question {
  final List<int> name;
  final int type;
  final int dnsClass;

  const _Question(this.name, this.type, this.dnsClass);

  bool matches(_Question other) {
    if (type != other.type ||
        dnsClass != other.dnsClass ||
        name.length != other.name.length) {
      return false;
    }
    for (var i = 0; i < name.length; i++) {
      if (name[i] != other.name[i]) return false;
    }
    return true;
  }
}

final class _WireMessage {
  final List<int> data;
  final List<_Question> questions = [];
  final List<int> ttlOffsets = [];
  int offset = 12;
  int? _optVersion;

  _WireMessage._(this.data);

  int get id => _u16(data, 0);
  int get flags => _u16(data, 2);
  bool get isResponse => flags & 0x8000 != 0;
  int get opcode => flags >> 11 & 0xf;

  factory _WireMessage.parse(List<int> bytes, {required bool query}) {
    if (bytes.length < 12 ||
        bytes.length > 65535 ||
        bytes.any((byte) => byte < 0 || byte > 255)) {
      throw _malformed;
    }
    final message = _WireMessage._(bytes);
    if (message.isResponse == query || _u16(bytes, 4) != 1) {
      throw query
          ? const DnssecMalformedResponseException('Invalid DNS wire query')
          : _malformed;
    }
    message._parse();
    return message;
  }

  void _need(int count, [int? limit]) {
    if (count < 0 || offset + count > (limit ?? data.length)) throw _malformed;
  }

  void _parse() {
    final counts = [
      _u16(data, 4),
      _u16(data, 6),
      _u16(data, 8),
      _u16(data, 10),
    ];
    for (var i = 0; i < counts[0]; i++) {
      final name = _name();
      _need(4);
      questions.add(
        _Question(name, _u16(data, offset), _u16(data, offset + 2)),
      );
      offset += 4;
    }
    for (var section = 1; section < 4; section++) {
      for (var i = 0; i < counts[section]; i++) {
        _record(additional: section == 3);
      }
    }
    if (offset != data.length) throw _malformed;
  }

  void _record({required bool additional}) {
    final ownerOffset = offset;
    final owner = _name();
    _need(10);
    final type = _u16(data, offset);
    final ttlOffset = offset + 4;
    final rdLength = _u16(data, offset + 8);
    final rdata = offset + 10;
    final end = rdata + rdLength;
    if (end > data.length) throw _malformed;
    if (type == 41) {
      if (!additional ||
          _optVersion != null ||
          owner.length != 1 ||
          owner.single != 0) {
        throw _malformed;
      }
      _optVersion = data[offset + 5];
      if (_optVersion != 0) throw _malformed;
      for (var at = rdata; at < end;) {
        if (at + 4 > end) throw _malformed;
        at += 4 + _u16(data, at + 2);
        if (at > end) throw _malformed;
      }
    } else {
      ttlOffsets.add(ttlOffset);
    }
    offset = end;
    if (ownerOffset >= offset) throw _malformed;
  }

  List<int> _name() {
    final output = <int>[];
    final start = offset;
    var cursor = offset;
    var jumped = false;
    final visited = <int>{};
    while (true) {
      if (cursor >= data.length || !visited.add(cursor)) throw _malformed;
      final length = data[cursor];
      if (length == 0) {
        output.add(0);
        if (!jumped) offset = cursor + 1;
        break;
      }
      if (length & 0xc0 == 0xc0) {
        if (cursor + 1 >= data.length) throw _malformed;
        final target = (length & 0x3f) << 8 | data[cursor + 1];
        if (target >= start) throw _malformed;
        if (!jumped) offset = cursor + 2;
        jumped = true;
        cursor = target;
        continue;
      }
      if (length & 0xc0 != 0 ||
          length > 63 ||
          cursor + 1 + length > data.length) {
        throw _malformed;
      }
      output.add(length);
      for (var i = cursor + 1; i <= cursor + length; i++) {
        final byte = data[i];
        output.add(byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte);
      }
      if (output.length >= 255) throw _malformed;
      cursor += 1 + length;
      if (!jumped) offset = cursor;
    }
    if (output.length > 255) throw _malformed;
    return List<int>.unmodifiable(output);
  }
}
