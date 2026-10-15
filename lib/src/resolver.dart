import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as native;
import 'dns.dart';
import 'wire.dart';

class DnssecResult {
  final String question;
  final int recordType;
  final String canonicalName;
  final Uri resolver;
  final DnssecStatus status;
  final List<DnssecRecord> records;
  final List<DnssecRecord> aliases;
  final List<DnssecTxtRecord> _txtRecords;

  DnssecResult({
    required this.question,
    required this.recordType,
    required this.canonicalName,
    required this.resolver,
    required this.status,
    required List<DnssecRecord> records,
    required List<DnssecRecord> aliases,
    required List<DnssecTxtRecord> txtRecords,
  }) : records = List.unmodifiable(records),
       aliases = List.unmodifiable(aliases),
       _txtRecords = List.unmodifiable(txtRecords);

  List<DnssecTxtRecord> secureTxt() {
    if (status != DnssecStatus.secure) {
      throw DnssecValidationException(status);
    }
    const malformed = DnssecMalformedResponseException(
      'Invalid secure TXT result',
    );
    if (recordType != 16 ||
        records.isEmpty ||
        records.length > 64 ||
        records.length != _txtRecords.length ||
        aliases.length > 7) {
      throw malformed;
    }

    late final String normalizedQuestion;
    late final String normalizedCanonical;
    try {
      normalizedQuestion = normalizeDnssecName(question);
      normalizedCanonical = normalizeDnssecName(canonicalName);
    } on DnssecException {
      throw malformed;
    }
    if (question != normalizedQuestion ||
        canonicalName != normalizedCanonical) {
      throw malformed;
    }

    var owner = normalizedQuestion;
    final seen = <String>{owner};
    for (final alias in aliases) {
      late final String aliasName;
      late final String target;
      try {
        aliasName = normalizeDnssecName(alias.name);
        target = normalizeDnssecName(alias.data);
      } on DnssecException {
        throw malformed;
      }
      if (alias.type != 5 ||
          alias.ttl < 0 ||
          alias.ttl > 0xffffffff ||
          alias.name != aliasName ||
          aliasName != owner ||
          !seen.add(target)) {
        throw malformed;
      }
      owner = target;
    }
    if (owner != normalizedCanonical) throw malformed;

    final txt = <DnssecTxtRecord>[];
    for (var i = 0; i < records.length; i++) {
      final record = records[i];
      final value = _txtRecords[i];
      late final String recordName;
      late final String txtName;
      try {
        recordName = normalizeDnssecName(record.name);
        txtName = normalizeDnssecName(value.name);
      } on DnssecException {
        throw malformed;
      }
      if (record.type != 16 ||
          record.ttl < 0 ||
          record.ttl > 0xffffffff ||
          value.ttl < 0 ||
          value.ttl > 0xffffffff ||
          record.name != recordName ||
          value.name != txtName ||
          recordName != normalizedCanonical ||
          txtName != normalizedCanonical ||
          record.ttl != value.ttl) {
        throw malformed;
      }
      txt.add(
        DnssecTxtRecord(name: txtName, ttl: value.ttl, bytes: value.bytes),
      );
    }
    return List.unmodifiable(txt);
  }
}

const _abiVersion = 1;
bool _abiChecked = false;

void _checkAbi() {
  if (_abiChecked) return;
  int version;
  try {
    version = native.abiVersion();
  } catch (error, stack) {
    throw DnssecUnavailableException(
      'DNSSEC validator library unavailable',
      cause: error,
      causeStackTrace: stack,
    );
  }
  if (version != _abiVersion) {
    throw DnssecUnavailableException(
      'DNSSEC validator ABI $version is not supported',
    );
  }
  _abiChecked = true;
}

class DnssecResolver {
  final DnssecWireTransport transport;
  final Uri endpoint;
  final Duration timeout;
  final int maxQueries;
  final String? trustAnchors;

  DnssecResolver({
    required this.transport,
    Uri? endpoint,
    this.timeout = const Duration(seconds: 20),
    this.maxQueries = 64,
    this.trustAnchors,
  }) : endpoint = endpoint ?? Uri.https('dns.google', '/dns-query') {
    if (!_isUsableDohEndpoint(this.endpoint) ||
        timeout.inMilliseconds < 1 ||
        timeout > const Duration(minutes: 2) ||
        maxQueries < 1 ||
        maxQueries > 128 ||
        (trustAnchors != null &&
            (trustAnchors!.trim().isEmpty ||
                utf8.encode(trustAnchors!).length > 60000))) {
      throw ArgumentError('Invalid DNSSEC resolver configuration');
    }
  }

  Future<DnssecResult> lookup(String domain, {int recordType = 16}) async =>
      startLookup(domain, recordType: recordType).result;

  Future<List<DnssecTxtRecord>> lookupTxt(String domain) async =>
      startTxtLookup(domain).result;

  DnssecOperation<List<DnssecTxtRecord>> startTxtLookup(String domain) {
    final operation = startLookup(domain);
    return DnssecOperation(
      operation.result.then((result) => result.secureTxt()),
      operation.cancel,
    );
  }

  DnssecOperation<DnssecResult> startLookup(
    String domain, {
    int recordType = 16,
  }) {
    try {
      domain = normalizeDnssecName(domain);
    } on DnssecInvalidNameException {
      rethrow;
    }
    // A, CNAME, TXT, AAAA.
    if (!const {1, 5, 16, 28}.contains(recordType)) {
      throw ArgumentError.value(recordType, 'recordType');
    }
    _checkAbi();
    final config = utf8.encode(
      jsonEncode({
        'name': '$domain.',
        'record_type': recordType,
        // The Dart deadline must fire first so a timeout is never reported as
        // an unavailable validator.
        'timeout_ms': timeout.inMilliseconds + 1000,
        'max_queries': maxQueries,
        'trust_anchors': trustAnchors,
      }),
    );
    final pointer = calloc<Uint8>(config.length);
    late final int handle;
    try {
      pointer.asTypedList(config.length).setAll(0, config);
      handle = native.start(pointer, config.length);
    } finally {
      calloc.free(pointer);
    }
    if (handle == 0) {
      throw const DnssecUnavailableException(
        'DNSSEC validator unavailable or busy',
      );
    }
    final result = Completer<DnssecResult>();
    final pending = <int, DnssecOperation<DnssecWireResponse>>{};
    Timer? pollTimer;
    Timer? deadline;
    var done = false;

    void cancelTransport(DnssecOperation<DnssecWireResponse>? exchange) {
      try {
        exchange?.cancel();
      } catch (_) {}
    }

    void close() {
      if (done) return;
      done = true;
      pollTimer?.cancel();
      deadline?.cancel();
      native.release(handle);
      for (final exchange in pending.values.toList()) {
        cancelTransport(exchange);
      }
      pending.clear();
    }

    void fail(Object error, [StackTrace? stack]) {
      if (done) return;
      close();
      result.completeError(error, stack);
    }

    Future<void> exchange(int id, Uint8List bytes) async {
      try {
        if (done) return;
        final query = List<int>.unmodifiable(bytes);
        final operation = transport.startWire(
          endpoint,
          query,
          maxResponseBytes: 65535,
        );
        pending[id] = operation;
        final response = await operation.result;
        if (done) return;
        // Re-checked here so a custom transport cannot bypass the bounds.
        if (response.statusCode != 200) {
          throw DnssecTransportException(
            'DNS HTTPS request failed',
            httpStatus: response.statusCode,
          );
        }
        if (response.body.length > 65535) {
          throw const DnssecResponseTooLargeException('DNS body exceeds limit');
        }
        // Match the exact native query before applying Age. This package owns
        // both checks and does not trust a port implementation to do either.
        final body = validateAndAgeDnssecWireResponse(
          query,
          response.body,
          age: response.age,
        );
        final pointer = calloc<Uint8>(body.length + 1);
        try {
          pointer.asTypedList(body.length).setAll(0, body);
          native.answer(handle, id, pointer, body.length);
        } finally {
          calloc.free(pointer);
        }
      } catch (error, stack) {
        fail(_mapPortFailure(error, stack), stack);
      } finally {
        cancelTransport(pending.remove(id));
      }
    }

    void poll() {
      try {
        for (var i = 0; i < 16 && !done; i++) {
          final pointer = native.poll(handle);
          if (pointer == nullptr) break;
          late final Map<String, dynamic> event;
          try {
            event =
                jsonDecode(pointer.cast<Utf8>().toDartString())
                    as Map<String, dynamic>;
          } finally {
            native.free(pointer);
          }
          if (event.containsKey('query')) {
            unawaited(
              exchange(
                event['id'] as int,
                base64Decode(event['query'] as String),
              ),
            );
            continue;
          }
          if (event.containsKey('error')) {
            final name = event['error'];
            throw _nativeFailure(name);
          }
          final value = event['result'] as Map<String, dynamic>;
          final statusName = value['status'];
          final status = DnssecStatus.values
              .where((item) => item.name == statusName)
              .firstOrNull;
          if (status == null) {
            throw _nativeFailure(statusName);
          }
          DnssecRecord record(dynamic raw) => DnssecRecord(
            name: normalizeDnssecName(raw['name'] as String),
            type: raw['record_type'] as int,
            ttl: raw['ttl'] as int,
            data: raw['data'] as String,
          );
          final rawRecords = value['records'] as List;
          final outcome = DnssecResult(
            question: domain,
            recordType: recordType,
            canonicalName: normalizeDnssecName(
              value['canonical_name'] as String,
            ),
            resolver: endpoint,
            status: status,
            records: rawRecords.map(record).toList(),
            aliases: (value['aliases'] as List).map(record).toList(),
            txtRecords: rawRecords
                .where((raw) => raw['txt'] != null)
                .map(
                  (raw) => DnssecTxtRecord(
                    name: normalizeDnssecName(raw['name'] as String),
                    ttl: raw['ttl'] as int,
                    bytes: (raw['txt'] as List).cast<int>(),
                  ),
                )
                .toList(),
          );
          close();
          result.complete(outcome);
        }
      } catch (error, stack) {
        fail(
          error is DnssecException
              ? error
              : DnssecMalformedResponseException(
                  'Invalid native DNS result',
                  cause: error,
                  causeStackTrace: stack,
                ),
          stack,
        );
      }
    }

    pollTimer = Timer.periodic(const Duration(milliseconds: 5), (_) => poll());
    deadline = Timer(
      timeout,
      () => fail(
        DnssecTimeoutException('DNSSEC lookup timed out', timeout: timeout),
      ),
    );
    return DnssecOperation(
      result.future,
      () => fail(const DnssecCancelledException('DNSSEC lookup cancelled')),
    );
  }
}

bool _isUsableDohEndpoint(Uri uri) {
  if (uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasFragment) {
    return false;
  }
  try {
    return uri.port >= 1 && uri.port <= 65535;
  } on FormatException {
    return false;
  }
}

DnssecException _mapPortFailure(Object error, StackTrace stack) {
  if (error is DnssecException) return error;
  return DnssecTransportException(
    'DNS transport failed',
    cause: error,
    causeStackTrace: stack,
  );
}

DnssecException _nativeFailure(Object? name) {
  final code = _errorNamed(name) ?? DnssecError.unavailable;
  final message = 'DNSSEC validator failed: $name';
  return switch (code) {
    DnssecError.secure ||
    DnssecError.insecure ||
    DnssecError.bogus ||
    DnssecError.indeterminate => DnssecValidationException(
      _statusNamed(name) ?? DnssecStatus.indeterminate,
      message: message,
    ),
    DnssecError.aliasAmbiguous => DnssecAliasAmbiguousException(message),
    DnssecError.aliasTooLong => DnssecAliasTooLongException(message),
    DnssecError.aliasLoop => DnssecAliasLoopException(message),
    DnssecError.noRecords => DnssecNoRecordsException(message),
    DnssecError.invalidName => DnssecInvalidNameException(message),
    DnssecError.responseTooLarge => DnssecResponseTooLargeException(message),
    DnssecError.questionMismatch => DnssecQuestionMismatchException(message),
    DnssecError.queryFailed => DnssecQueryFailedException(message),
    DnssecError.transport => DnssecTransportException(message),
    DnssecError.cancelled => DnssecCancelledException(message),
    DnssecError.timedOut => DnssecTimeoutException(
      message,
      timeout: Duration.zero,
    ),
    DnssecError.malformedResponse => DnssecMalformedResponseException(message),
    DnssecError.unavailable => DnssecUnavailableException(message),
  };
}

DnssecError? _errorNamed(Object? name) {
  if (name is! String) return null;
  return DnssecError.values.where((item) => item.name == name).firstOrNull;
}

DnssecStatus? _statusNamed(Object? name) {
  if (name is! String) return null;
  return DnssecStatus.values.where((item) => item.name == name).firstOrNull;
}
