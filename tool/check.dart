// Runs package checks from the repository root, stopping at the first failure.
// Usage: dart tool/check.dart
import 'dart:io';

const _manifest = ['--manifest-path', 'native/Cargo.toml'];

const _steps = [
  ['dart', 'pub', 'get', '--no-example'],
  [
    'dart',
    'format',
    '--output=none',
    '--set-exit-if-changed',
    'lib',
    'test',
    'hook',
    'tool',
    'example',
  ],
  ['dart', 'analyze', '--fatal-infos'],
  ['cargo', '+1.90.0', 'fmt', ..._manifest, '--all', '--', '--check'],
  [
    'cargo',
    '+1.90.0',
    'clippy',
    '--locked',
    ..._manifest,
    '--all-targets',
    '--',
    '-D',
    'warnings',
  ],
  ['cargo', '+1.90.0', 'test', '--locked', ..._manifest],
  ['dart', 'test', '--reporter', 'expanded'],
  ['dart', 'pub', 'publish', '--dry-run'],
];

Future<void> main() async {
  final root = File.fromUri(Platform.script).parent.parent.path;
  for (final [tool, ...args] in _steps) {
    final command = '$tool ${args.join(' ')}';
    stdout.writeln('\$ $command');
    final process = await Process.start(
      tool == 'dart' ? Platform.resolvedExecutable : tool,
      args,
      workingDirectory: root,
      mode: ProcessStartMode.inheritStdio,
    );
    final code = await process.exitCode;
    if (code != 0) {
      stderr.writeln('Check failed: $command (exit $code)');
      exit(code);
    }
  }
}
