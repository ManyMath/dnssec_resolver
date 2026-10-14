import 'package:dnssec_resolver/dnssec_resolver.dart';

Future<void> printSecureTxt(DohWireTransport transport, String domain) async {
  final result = await DnssecResolver(transport: transport).lookupTxt(domain);
  for (final record in result) {
    print(record.text);
  }
}
