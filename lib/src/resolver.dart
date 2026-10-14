import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:doh_transport/doh_transport.dart';
import 'package:ffi/ffi.dart';

import 'bindings.dart' as native;

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
  queryFailed,
  unavailable,
  cancelled,
  timedOut,
  malformedResponse,
}

final class DnssecException extends DnsException {
  final DnssecError code;
  final DnssecStatus? status;

  const DnssecException(this.code, super.message, {this.status});

  @override
  String toString() => 'DnssecException(${code.name}): $message';
}

class DnssecOperation<T> {
  final Future<T> result;
  final void Function() cancel;

  const DnssecOperation(this.result, this.cancel);
}

class DnssecResult {
  final String question;
  final int recordType;
  final String canonicalName;
  final Uri resolver;
  final DnssecStatus status;
  final List<DnsRecord> records;
  final List<DnsRecord> aliases;
  final List<DnsTxtRecord> _txtRecords;

  DnssecResult({
    required this.question,
    required this.recordType,
    required this.canonicalName,
    required this.resolver,
    required this.status,
    required List<DnsRecord> records,
    required List<DnsRecord> aliases,
    required List<DnsTxtRecord> txtRecords,
  }) : records = List.unmodifiable(records),
       aliases = List.unmodifiable(aliases),
       _txtRecords = List.unmodifiable(txtRecords);

  List<DnsTxtRecord> secureTxt() {
    if (status != DnssecStatus.secure) {
      throw DnssecException(
        DnssecError.values.byName(status.name),
        'DNSSEC validation did not establish a secure answer',
        status: status,
      );
    }
    const malformed = DnssecException(
      DnssecError.malformedResponse,
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
      normalizedQuestion = normalizeDnsName(question);
      normalizedCanonical = normalizeDnsName(canonicalName);
    } on DnsException {
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
        aliasName = normalizeDnsName(alias.name);
        target = normalizeDnsName(alias.data);
      } on DnsException {
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

    final txt = <DnsTxtRecord>[];
    for (var i = 0; i < records.length; i++) {
      final record = records[i];
      final value = _txtRecords[i];
      late final String recordName;
      late final String txtName;
      try {
        recordName = normalizeDnsName(record.name);
        txtName = normalizeDnsName(value.name);
      } on DnsException {
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
      txt.add(DnsTxtRecord(name: txtName, ttl: value.ttl, bytes: value.bytes));
    }
    return List.unmodifiable(txt);
  }
}

class DnssecResolver {
  static final Object validator = Object();

  final DohWireTransport transport;
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
    if (!isUsableDohEndpoint(this.endpoint) ||
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

  Future<List<DnsTxtRecord>> lookupTxt(String domain) async =>
      startTxtLookup(domain).result;

  DnssecOperation<List<DnsTxtRecord>> startTxtLookup(String domain) {
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
      domain = normalizeDnsName(domain);
    } on DnsInvalidNameException catch (error) {
      throw DnssecException(DnssecError.invalidName, error.message);
    }
    // A, CNAME, TXT, AAAA.
    if (!const {1, 5, 16, 28}.contains(recordType)) {
      throw ArgumentError.value(recordType, 'recordType');
    }
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
      throw const DnssecException(
        DnssecError.unavailable,
        'DNSSEC validator unavailable or busy',
      );
    }
    final result = Completer<DnssecResult>();
    final pending = <int, DnsOperation<DohHttpResponse>>{};
    Timer? pollTimer;
    Timer? deadline;
    var done = false;

    void cancelTransport(DnsOperation<DohHttpResponse>? exchange) {
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
        final operation = transport.startWire(
          endpoint,
          bytes,
          maxResponseBytes: 65535,
        );
        pending[id] = operation;
        final response = await operation.result;
        if (done) return;
        // Re-checked here so a custom transport cannot bypass the bounds.
        if (response.statusCode != 200) {
          throw DnsTransportException(
            'DNS HTTPS request failed',
            httpStatus: response.statusCode,
          );
        }
        if (response.body.length > 65535) {
          throw const DnsResponseTooLargeException('DNS body exceeds limit');
        }
        // Also zeroes high-bit TTLs (RFC 2181), so it runs even at age zero.
        final body = adjustDnsWireTtls(response.body, age: response.age);
        final pointer = calloc<Uint8>(body.length + 1);
        try {
          pointer.asTypedList(body.length).setAll(0, body);
          native.answer(handle, id, pointer, body.length);
        } finally {
          calloc.free(pointer);
        }
      } catch (error, stack) {
        fail(
          error is DnsException
              ? error
              : const DnsTransportException('DNS transport failed'),
          stack,
        );
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
            throw DnssecException(
              _errorNamed(name) ?? DnssecError.unavailable,
              'DNSSEC validator failed: $name',
              status: _statusNamed(name),
            );
          }
          final value = event['result'] as Map<String, dynamic>;
          final statusName = value['status'];
          final status = DnssecStatus.values
              .where((item) => item.name == statusName)
              .firstOrNull;
          if (status == null) {
            throw DnssecException(
              _errorNamed(statusName) ?? DnssecError.indeterminate,
              'DNSSEC lookup $statusName',
            );
          }
          DnsRecord record(dynamic raw) => DnsRecord(
            name: normalizeDnsName(raw['name'] as String),
            type: raw['record_type'] as int,
            ttl: raw['ttl'] as int,
            data: raw['data'] as String,
          );
          final rawRecords = value['records'] as List;
          final outcome = DnssecResult(
            question: domain,
            recordType: recordType,
            canonicalName: normalizeDnsName(value['canonical_name'] as String),
            resolver: endpoint,
            status: status,
            records: rawRecords.map(record).toList(),
            aliases: (value['aliases'] as List).map(record).toList(),
            txtRecords: rawRecords
                .where((raw) => raw['txt'] != null)
                .map(
                  (raw) => DnsTxtRecord(
                    name: normalizeDnsName(raw['name'] as String),
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
              : const DnssecException(
                  DnssecError.malformedResponse,
                  'Invalid native DNS result',
                ),
          stack,
        );
      }
    }

    pollTimer = Timer.periodic(const Duration(milliseconds: 5), (_) => poll());
    deadline = Timer(
      timeout,
      () => fail(
        const DnssecException(DnssecError.timedOut, 'DNSSEC lookup timed out'),
      ),
    );
    return DnssecOperation(
      result.future,
      () => fail(
        const DnssecException(DnssecError.cancelled, 'DNSSEC lookup cancelled'),
      ),
    );
  }
}

DnssecError? _errorNamed(Object? name) {
  if (name is! String) return null;
  return DnssecError.values.where((item) => item.name == name).firstOrNull;
}

DnssecStatus? _statusNamed(Object? name) {
  if (name is! String) return null;
  return DnssecStatus.values.where((item) => item.name == name).firstOrNull;
}
