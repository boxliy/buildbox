import 'dart:io';

import 'package:buildbox_tools/src/core.dart';
import 'package:test/test.dart';

void main() {
  test(
    'curl_retry retries transient exit 35 without extra curl flags',
    () async {
      final bin = await Directory.systemTemp.createTemp('curl-retry-bin-');
      final count = File('${bin.path}/attempts');
      final argv = File('${bin.path}/argv.log');
      final curl = File('${bin.path}/curl');
      await curl.writeAsString('''#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "\$*" >>"\$CURL_ARGV_LOG"
attempt=0
if [[ -f "\$CURL_ATTEMPT_FILE" ]]; then
  attempt=\$(cat "\$CURL_ATTEMPT_FILE")
fi
attempt=\$((attempt + 1))
printf '%s' "\$attempt" >"\$CURL_ATTEMPT_FILE"
if [[ "\$attempt" -eq 1 ]]; then
  printf 'tls reset\\n' >&2
  exit 35
fi
printf 'ready'
''');
      await Process.run('chmod', ['755', curl.path]);
      final script =
          '''
set -euo pipefail
source "${Directory.current.path}/scripts/lib/curl_retry.sh"
export PATH="${bin.path}:\$PATH"
export BUILDBOX_RETRY_DELAY=0
export CURL_ATTEMPT_FILE="${count.path}"
export CURL_ARGV_LOG="${argv.path}"
curl_retry --fail --silent --show-error https://example.invalid/probe
''';
      final result = await Process.run('bash', ['-c', script]);
      expect(result.exitCode, 0, reason: '${result.stdout}${result.stderr}');
      expect(result.stdout, 'ready');
      expect(result.stderr, contains('tls reset'));
      expect(count.readAsStringSync(), '2');
      expect(
        argv.readAsLinesSync(),
        List.filled(
          2,
          '--fail --silent --show-error https://example.invalid/probe',
        ),
      );
      await bin.delete(recursive: true);
    },
  );

  test(
    'request retries transient TLS failures and stops after four attempts',
    () async {
      var calls = 0;
      final value = await withTransientRetry(() async {
        calls += 1;
        if (calls < 3) throw const HandshakeException('unexpected eof');
        return 'ok';
      }, delay: Duration.zero);
      expect(value, 'ok');
      expect(calls, 3);

      calls = 0;
      await expectLater(
        withTransientRetry(() async {
          calls += 1;
          throw const SocketException('reset');
        }, delay: Duration.zero),
        throwsA(isA<SocketException>()),
      );
      expect(calls, 4);

      calls = 0;
      await expectLater(
        withTransientRetry(() async {
          calls += 1;
          throw const FormatException('rejected');
        }, delay: Duration.zero),
        throwsA(isA<FormatException>()),
      );
      expect(calls, 1);
    },
  );
}
