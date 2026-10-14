import 'dart:io';

import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    await RustBuilder(
      assetName: 'src/bindings.dart',
      extraCargoBuildArgs: ['--locked'],
    ).run(input: input, output: output);
    for (final path in [
      'native/Cargo.toml',
      'native/Cargo.lock',
      'native/rust-toolchain.toml',
    ]) {
      final uri = input.packageRoot.resolve(path);
      if (File.fromUri(uri).existsSync()) output.dependencies.add(uri);
    }
  });
}
