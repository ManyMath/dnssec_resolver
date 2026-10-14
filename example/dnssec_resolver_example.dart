import 'dart:async';
import 'dart:io';

import 'package:dnssec_resolver/dnssec_resolver.dart';

/// Posts wire queries to Google Public DNS over HTTPS.
class HttpWireTransport implements DnssecWireTransport {
  final _client = HttpClient();

  @override
  DnssecOperation<DnssecWireResponse> startWire(
    List<int> query, {
    required int maxResponseBytes,
  }) {
    HttpClientRequest? request;
    final result = () async {
      request = await _client.postUrl(
        Uri.parse('https://dns.google/dns-query'),
      );
      request!.headers
        ..set(HttpHeaders.acceptHeader, 'application/dns-message')
        ..set(HttpHeaders.contentTypeHeader, 'application/dns-message');
      request!.add(query);
      final response = await request!.close();
      if (response.statusCode != 200) {
        throw HttpException('HTTP ${response.statusCode}');
      }
      final body = <int>[];
      await for (final chunk in response) {
        body.addAll(chunk);
        if (body.length > maxResponseBytes) {
          throw const DnssecResponseTooLargeException('Response too large');
        }
      }
      final age = int.tryParse(response.headers.value('age') ?? '') ?? 0;
      return DnssecWireResponse(body, age: Duration(seconds: age));
    }();
    return DnssecOperation(result, () => request?.abort());
  }

  void close() => _client.close(force: true);
}

Future<void> main(List<String> args) async {
  final transport = HttpWireTransport();
  try {
    final resolver = DnssecResolver(transport: transport);
    for (final record in await resolver.lookupTxt(
      args.firstOrNull ?? 'example.com',
    )) {
      print(record.text);
    }
  } on DnssecException catch (error) {
    print(error);
    exitCode = 1;
  } finally {
    transport.close();
  }
}
