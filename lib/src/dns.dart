import 'dart:async';
import 'dart:convert';
import 'dart:math';

enum DnssecStatus { secure, insecure, bogus, indeterminate }

enum DnssecError {
  secure,
  insecure,
  bogus,
  indeterminate,
  aliasAmbiguous,
  aliasTooLong,
  aliasLoop,
  noRecords,
  invalidName,
  responseTooLarge,
  questionMismatch,
  queryFailed,
  transport,
  unavailable,
  cancelled,
  timedOut,
  malformedResponse,
}

sealed class DnssecException implements Exception {
  final DnssecError code;
  final String message;
  final DnssecStatus? status;
  final Object? cause;
  final StackTrace? causeStackTrace;

  const DnssecException(
    this.code,
    this.message, {
    this.status,
    this.cause,
    this.causeStackTrace,
  });

  @override
  String toString() {
    final details = switch (this) {
      DnssecQueryFailedException(:final rcode) when rcode != null =>
        ', rcode: $rcode',
      DnssecTransportException(:final httpStatus) when httpStatus != null =>
        ', httpStatus: $httpStatus',
      DnssecTimeoutException(:final timeout) => ', timeout: $timeout',
      _ when status != null => ', status: ${status!.name}',
      _ => '',
    };
    return '$runtimeType(code: ${code.name}$details): $message';
  }
}

final class DnssecValidationException extends DnssecException {
  DnssecValidationException(
    DnssecStatus status, {
    String message = 'DNSSEC validation did not establish a secure answer',
  }) : super(DnssecError.values.byName(status.name), message, status: status);
}

final class DnssecAliasAmbiguousException extends DnssecException {
  const DnssecAliasAmbiguousException(String message)
    : super(DnssecError.aliasAmbiguous, message);
}

final class DnssecAliasTooLongException extends DnssecException {
  const DnssecAliasTooLongException(String message)
    : super(DnssecError.aliasTooLong, message);
}

final class DnssecAliasLoopException extends DnssecException {
  const DnssecAliasLoopException(String message)
    : super(DnssecError.aliasLoop, message);
}

final class DnssecNoRecordsException extends DnssecException {
  const DnssecNoRecordsException(String message)
    : super(DnssecError.noRecords, message);
}

final class DnssecInvalidNameException extends DnssecException {
  const DnssecInvalidNameException(String message)
    : super(DnssecError.invalidName, message);
}

final class DnssecResponseTooLargeException extends DnssecException {
  const DnssecResponseTooLargeException(String message)
    : super(DnssecError.responseTooLarge, message);
}

final class DnssecQuestionMismatchException extends DnssecException {
  const DnssecQuestionMismatchException(String message)
    : super(DnssecError.questionMismatch, message);
}

final class DnssecQueryFailedException extends DnssecException {
  final int? rcode;

  const DnssecQueryFailedException(String message, {this.rcode})
    : super(DnssecError.queryFailed, message);
}

final class DnssecTransportException extends DnssecException {
  final int? httpStatus;

  const DnssecTransportException(
    String message, {
    this.httpStatus,
    super.cause,
    super.causeStackTrace,
  }) : super(DnssecError.transport, message);
}

final class DnssecUnavailableException extends DnssecException {
  const DnssecUnavailableException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(DnssecError.unavailable, message);
}

final class DnssecCancelledException extends DnssecException {
  const DnssecCancelledException(String message)
    : super(DnssecError.cancelled, message);
}

final class DnssecTimeoutException extends DnssecException {
  final Duration timeout;

  const DnssecTimeoutException(String message, {required this.timeout})
    : super(DnssecError.timedOut, message);
}

final class DnssecMalformedResponseException extends DnssecException {
  const DnssecMalformedResponseException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(DnssecError.malformedResponse, message);
}

class DnssecOperation<T> {
  final Future<T> result;
  final void Function() cancel;

  DnssecOperation(this.result, this.cancel) {
    result.ignore();
  }

  factory DnssecOperation.failed(DnssecException error) =>
      DnssecOperation(Future<T>.error(error), () {});
}

final class DnssecWireResponse {
  final List<int> message;

  /// Time the message spent in caches, such as an HTTP `Age`. It is
  /// subtracted from every TTL before validation.
  final Duration age;

  DnssecWireResponse(List<int> message, {this.age = Duration.zero})
    : message = List<int>.unmodifiable(message) {
    if (age < Duration.zero) throw ArgumentError.value(age, 'age');
    if (this.message.any((byte) => byte < 0 || byte > 255)) {
      throw ArgumentError.value(
        message,
        'message',
        'DNS message must contain octets',
      );
    }
  }
}

abstract interface class DnssecWireTransport {
  /// Sends one DNS wire [query] upstream. Implementations stop reading a
  /// response after [maxResponseBytes] and report every failure through the
  /// returned operation.
  DnssecOperation<DnssecWireResponse> startWire(
    List<int> query, {
    required int maxResponseBytes,
  });
}

final _label = RegExp(r'^[a-z0-9_-]+$');

String normalizeDnssecName(String name) {
  if (name.codeUnits.any((code) => code > 0x7f)) {
    throw const DnssecInvalidNameException('Use ASCII DNS names');
  }
  final value = (name.endsWith('.') ? name.substring(0, name.length - 1) : name)
      .toLowerCase();
  if (value.isEmpty ||
      value.length > 253 ||
      !value
          .split('.')
          .every(
            (label) =>
                label.isNotEmpty &&
                label.length <= 63 &&
                _label.hasMatch(label),
          )) {
    throw const DnssecInvalidNameException('Invalid ASCII DNS name');
  }
  return value;
}

int effectiveDnssecTtl(int ttl, {Duration age = Duration.zero}) {
  if (ttl < 0 || ttl > 0xffffffff) throw ArgumentError.value(ttl, 'ttl');
  if (age < Duration.zero) throw ArgumentError.value(age, 'age');
  return max(0, (ttl > 0x7fffffff ? 0 : ttl) - age.inSeconds);
}

class DnssecRecord {
  final String name;
  final int type;
  final int ttl;
  final String data;

  /// The TXT character-strings concatenated, or null for other types.
  final List<int>? txt;

  DnssecRecord({
    required this.name,
    required this.type,
    required this.ttl,
    required this.data,
    List<int>? txt,
  }) : txt = txt == null ? null : List<int>.unmodifiable(txt) {
    if (this.txt?.any((byte) => byte < 0 || byte > 255) ?? false) {
      throw ArgumentError.value(txt, 'txt', 'TXT data must contain octets');
    }
  }
}

class DnssecTxtRecord {
  final String name;
  final int ttl;
  final List<int> bytes;

  DnssecTxtRecord({
    required this.name,
    required this.ttl,
    required List<int> bytes,
  }) : bytes = List<int>.unmodifiable(bytes) {
    if (this.bytes.any((byte) => byte < 0 || byte > 255)) {
      throw ArgumentError.value(bytes, 'bytes', 'TXT data must contain octets');
    }
  }

  String get text {
    try {
      return utf8.decode(bytes);
    } on FormatException catch (error, stack) {
      throw DnssecMalformedResponseException(
        'TXT is not UTF-8',
        cause: error,
        causeStackTrace: stack,
      );
    }
  }
}
