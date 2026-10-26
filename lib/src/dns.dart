import 'dart:async';
import 'dart:convert';

enum DnssecStatus { secure, insecure, bogus, indeterminate }

/// A lookup failed; [cause] carries the underlying error when there is one.
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

/// An owner had several CNAMEs, or a CNAME next to the queried records.
final class DnssecAliasAmbiguousException extends DnssecException {
  const DnssecAliasAmbiguousException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// The CNAME chain exceeded the alias limit.
final class DnssecAliasTooLongException extends DnssecException {
  const DnssecAliasTooLongException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// The CNAME chain revisited an owner.
final class DnssecAliasLoopException extends DnssecException {
  const DnssecAliasLoopException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// A secure NODATA or NXDOMAIN proof showed the record does not exist; an
/// empty answer without such a proof is reported by its DNSSEC status.
final class DnssecNoRecordException extends DnssecException {
  const DnssecNoRecordException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// The queried name is not a valid ASCII DNS name.
final class DnssecInvalidNameException extends DnssecException {
  const DnssecInvalidNameException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// A wire response or an answer set exceeded the size limit.
final class DnssecResponseTooLargeException extends DnssecException {
  const DnssecResponseTooLargeException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// A wire response did not answer the query that was sent.
final class DnssecQuestionMismatchException extends DnssecException {
  const DnssecQuestionMismatchException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// The upstream resolver answered with an error response code.
final class DnssecQueryFailedException extends DnssecException {
  const DnssecQueryFailedException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// The transport failed with an error that is not a [DnssecException].
final class DnssecTransportException extends DnssecException {
  const DnssecTransportException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// The native validator could not be loaded, started or completed.
final class DnssecUnavailableException extends DnssecException {
  const DnssecUnavailableException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// The lookup was cancelled.
final class DnssecCancelledException extends DnssecException {
  const DnssecCancelledException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// The lookup did not finish within [timeout].
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

/// A wire response or validator result could not be parsed or was invalid.
final class DnssecMalformedResponseException extends DnssecException {
  const DnssecMalformedResponseException(
    super.message, {
    super.cause,
    super.causeStackTrace,
  });
}

/// A started request. Starting never throws: every failure completes [result]
/// with a [DnssecException], and an unawaited [result] never raises an uncaught
/// error.
class DnssecOperation<T> {
  final Future<T> result;

  /// Fails an unfinished operation and releases its work. Repeated calls are
  /// safe.
  final void Function() cancel;

  DnssecOperation(this.result, this.cancel) {
    result.ignore();
  }

  /// The error is reported only to listeners of [result]; dropping it is safe.
  factory DnssecOperation.failed(DnssecException error) =>
      DnssecOperation(Future<T>.error(error), () {});
}

/// A DNS wire message returned by a [DnssecWireTransport].
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

/// Sends the validator's DNS wire queries upstream.
abstract interface class DnssecWireTransport {
  /// Sends one DNS wire [query] upstream and stops reading a response after
  /// [maxResponseBytes]. It must not throw: every failure completes the
  /// operation's `result`. An error that is not a [DnssecException] is wrapped
  /// as [DnssecTransportException] with the original in `cause`. `cancel` must
  /// be idempotent; it is also called once the result has completed. The
  /// response is matched against [query] and bounded again by the resolver.
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

/// A record from a validated answer.
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

/// A TXT record from a secure answer.
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
