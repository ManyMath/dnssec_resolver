import 'dart:ffi';

@Native<Uint64 Function(Pointer<Uint8>, Size)>(symbol: 'dnssec_start')
external int start(Pointer<Uint8> config, int length);

@Native<Pointer<Char> Function(Uint64)>(symbol: 'dnssec_poll')
external Pointer<Char> poll(int handle);

@Native<Void Function(Uint64, Uint64, Pointer<Uint8>, Size)>(
  symbol: 'dnssec_answer',
)
external void answer(int handle, int request, Pointer<Uint8> bytes, int length);

@Native<Void Function(Uint64)>(symbol: 'dnssec_release')
external void release(int handle);

@Native<Void Function(Pointer<Char>)>(symbol: 'dnssec_free')
external void free(Pointer<Char> value);
