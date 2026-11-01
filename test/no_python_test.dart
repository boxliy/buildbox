import 'dart:io';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';

void main() {
  test(
    'compile dispatch upload callback shell contract runs with no Python or FVM on PATH',
    () async {
      await temporary('without-python-', (dir) async {
        for (final command in [
          'bash',
          'sh',
          'dirname',
          'mktemp',
          'mkdir',
          'cat',
          'base64',
          'jq',
          'sha256sum',
          'awk',
          'sed',
          'grep',
          'cut',
          'env',
          'cp',
          'mv',
          'find',
          'basename',
          'readlink',
          'tail',
          'cmp',
          'chmod',
          'touch',
          'stat',
          'tr',
          'sort',
          'head',
          'uname',
          'rm',
          'rmdir',
          'git',
          'tee',
          'wc',
          'date',
        ]) {
          final result = await Process.run('which', [command]);
          if (result.exitCode == 0)
            Link(
              '${dir.path}/$command',
            ).createSync((result.stdout as String).trim());
        }
        Link('${dir.path}/dart').createSync(Platform.resolvedExecutable);
        final env = <String, String>{
          ...Platform.environment,
          'PATH': dir.path,
          'BUILDBOX_TEST_DART': Platform.resolvedExecutable,
          'PROMPT_COMMAND': '',
          'BASH_ENV': '/dev/null',
        };
        final absent = await Process.run(
          '${dir.path}/bash',
          [
            '-c',
            '! command -v python && ! command -v python3 && ! command -v fvm',
          ],
          environment: env,
          includeParentEnvironment: false,
        );
        expect(absent.exitCode, 0);
        final result = await Process.run(
          '${dir.path}/bash',
          ['tests/contract.sh'],
          environment: env,
          includeParentEnvironment: false,
        );
        expect(
          result.exitCode,
          0,
          reason: '${result.stdout}\n${result.stderr}',
        );
      });
    },
    timeout: const Timeout(Duration(minutes: 4)),
  );
}
