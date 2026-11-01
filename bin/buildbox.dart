import 'dart:io';
import 'package:buildbox_tools/src/commands.dart';

Future<void> main(List<String> args) async {
  try {
    await commands(args);
  } catch (_) {
    final command = args.isEmpty ? 'command' : args.first;
    stderr.writeln(
      command.startsWith('sign-')
          ? '$command: signing failed; no signed delivery was authorized'
          : 'buildbox: $command rejected input; no delivery authorized',
    );
    exitCode = 1;
  }
}
