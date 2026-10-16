import 'dart:async';
import 'dart:convert';

enum DnssecStatus { secure, insecure, bogus, indeterminate }

sealed class DnssecException implements Exception {
  final String message;
  final Object? cause;
  final StackTrace? causeStackTrace;

  const DnssecException(this.message, {this.cause, this.causeStackTrace});

  @override
  String toString() => '$runtimeType: $message';
}

/// The validator did not prove the answer secure.
final class DnssecValidationException extends DnssecException {
  final DnssecStatus status;

  DnssecValidationException(
    super.message, {
    required this.status,
    super.cause,
    super.causeStackTrace,
  }) {
    if (status == DnssecStatus.secure) {
      throw ArgumentError.value(status, 'status', 'Not a validation failure');
    }
  }

  @override
  String toString() => '$runtimeType(status: ${status.name}): $message';
}

final class DnssecAliasAmbiguousException extends DnssecException {
  const DnssecAliasAmbiguousException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecAliasTooLongException extends DnssecException {
  const DnssecAliasTooLongException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecAliasLoopException extends DnssecException {
  const DnssecAliasLoopException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecNoRecordsException extends DnssecException {
  const DnssecNoRecordsException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecInvalidNameException extends DnssecException {
  const DnssecInvalidNameException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecResponseTooLargeException extends DnssecException {
  const DnssecResponseTooLargeException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecQuestionMismatchException extends DnssecException {
  const DnssecQuestionMismatchException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecQueryFailedException extends DnssecException {
  const DnssecQueryFailedException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecTransportException extends DnssecException {
  const DnssecTransportException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecUnavailableException extends DnssecException {
  const DnssecUnavailableException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecCancelledException extends DnssecException {
  const DnssecCancelledException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

final class DnssecTimeoutException extends DnssecException {
  final Duration timeout;

  const DnssecTimeoutException(
    super.message, {
    required this.timeout,
    super.cause,
    super.causeStackTrace,
  });

  @override
  String toString() => '$runtimeType(timeout: $timeout): $message';
}

final class DnssecMalformedResponseException extends DnssecException {
  const DnssecMalformedResponseException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
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
    throw const DnssecInvalidNameException('DNS name is not ASCII');
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
