import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart' hide fail;
import 'package:yaml/yaml.dart';
import 'package:buildbox_tools/src/core.dart';

bool enabled(String? expression, Map<String, String> inputs, bool failed) {
  if (expression == null) return !failed;
  var source = expression.replaceAll(r'${{', '').replaceAll('}}', '').trim();
  if (!RegExp(r'\b(success|failure|always|cancelled)\(\)').hasMatch(source))
    source = 'success() && ($source)';
  final tokens = RegExp(
    r"success\(\)|failure\(\)|always\(\)|cancelled\(\)|inputs\.\w+|'[^']*'|==|!=|&&|\|\||[()]",
  ).allMatches(source).map((m) => m[0]!).toList();
  var i = 0;
  late dynamic Function() atom;
  late bool Function() and;
  late bool Function() or;
  atom = () {
    final t = tokens[i++];
    if (t == '(') {
      final result = or();
      require(tokens[i++] == ')', 'expression closing paren');
      return result;
    }
    if (t == 'success()') return !failed;
    if (t == 'failure()') return failed;
    if (t == 'always()') return true;
    if (t == 'cancelled()') return false;
    if (t.startsWith('inputs.')) return inputs[t.substring(7)];
    if (t.startsWith("'")) return t.substring(1, t.length - 1);
    return fail('unknown expression');
  };
  bool compare() {
    final left = atom();
    if (i < tokens.length && ['==', '!='].contains(tokens[i])) {
      final op = tokens[i++], right = atom();
      return op == '==' ? left == right : left != right;
    }
    return left as bool;
  }

  and = () {
    var result = compare();
    while (i < tokens.length && tokens[i] == '&&') {
      i++;
      final next = compare();
      result = result && next;
    }
    return result;
  };
  or = () {
    var result = and();
    while (i < tokens.length && tokens[i] == '||') {
      i++;
      final next = and();
      result = result || next;
    }
    return result;
  };
  final result = or();
  require(i == tokens.length, 'expression tail');
  return result;
}

Future<List<String>> execute(
  String prepare,
  String compile,
  String sign, {
  String? missing,
  bool uploadFailure = false,
}) async {
  final inputs = {
    'prepare_result': prepare,
    'compile_result': compile,
    'sign_result': sign,
    'failure_reason': 'fixture prepare failure',
  };
  return temporary('workflow-test-', (root) async {
    final repo = Directory.current.path;
    File('${root.path}/event.json').writeAsStringSync(
      jsonEncode({
        'inputs': {'dispatch_proof': 'a' * 64},
      }),
    );
    final env = <String, String>{
      ...Platform.environment,
      'PATH': '$repo/tests/bin:${Platform.environment['PATH']}',
      'BUILDBOX_TEST_DART': Platform.resolvedExecutable,
      'BUILDBOX_STATE_DIR': '${root.path}/state',
      'RUNNER_TEMP': root.path,
      'GITHUB_ENV': '${root.path}/env',
      'GITHUB_EVENT_PATH': '${root.path}/event.json',
      'BUILDBOX_RUN_ID': '401',
      'BUILDBOX_GITHUB_RUN_ID': '987654321',
      'HAWK_BASE_URL': 'https://hawk.example',
      'HAWK_OIDC_AUDIENCE': 'https://hawk.example/audience',
      'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'fixture-request',
      'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://oidc.example/token?request=1',
      'CURL_LOG': '${root.path}/curl.log',
      'FIXTURE_DIR': '$repo/tests/fixtures',
      'HAWK_CALLBACK_STAGE': 'finalize',
      'FAILURE_REASON': inputs['failure_reason']!,
      'MOCK_UPLOAD_FAIL': uploadFailure ? '1' : '0',
      'MOCK_CALLBACK_LOG': '${root.path}/callbacks.jsonl',
      'PROMPT_COMMAND': '',
      'BASH_ENV': '/dev/null',
    }..remove('HAWK_STAGE_TOKEN');
    var failed = false;
    final executed = <String>[];
    final yaml =
        loadYaml(File('.github/workflows/finalize.yml').readAsStringSync())
            as YamlMap;
    final steps = yaml['jobs']['finalize']['steps'] as YamlList;
    for (var index = 0; index < steps.length; index++) {
      final step = steps[index] as YamlMap, name = step['name'] as String;
      if (!enabled(step['if'] as String?, inputs, failed)) continue;
      executed.add(name);
      if (name.startsWith('Restore ')) {
        if (missing == name) {
          failed = true;
          continue;
        }
        final state = Directory('${root.path}/state')..createSync();
        if (name == 'Restore sign inputs') {
          writeJson('${state.path}/targets.json', ['apk']);
          File('${state.path}/spec.env').writeAsStringSync(
            "BUILDBOX_TARGETS_JSON='${state.path}/targets.json'\nBUILDBOX_ARTIFACT_PREFIX=builds/spec-apk-1/build-apk-1/\n",
          );
        } else {
          Directory('${state.path}/artifacts').createSync();
          final content = utf8.encode('signed fixture transport');
          File(
            '${state.path}/artifacts/swan-release.apk',
          ).writeAsBytesSync(content);
          writeJson('${state.path}/artifacts.json', [
            {
              'target': 'apk',
              'fileName': 'swan-release.apk',
              'byteSize': content.length,
              'sha256': 'sha256:${hashBytes(content)}',
              'signMode': 'signed',
            },
          ]);
          writeJson('${state.path}/sign-proof.json', {
            'signer': 'fixture-signer',
          });
        }
        continue;
      }
      if (step['run'] == null ||
          [
            'Initialize isolated state directory',
            'Resolve trusted Buildbox tools',
          ].contains(name))
        continue;
      var script = step['run'] as String;
      script = script.replaceAllMapped(
        RegExp(r'\$\{\{ inputs\.(\w+) \}\}'),
        (m) => inputs[m[1]]!,
      );
      final commandFile = File('${root.path}/env-$index')
        ..writeAsStringSync('');
      env['GITHUB_ENV'] = commandFile.path;
      final result = await Process.run(
        'bash',
        ['-euo', 'pipefail', '-c', script],
        environment: env,
        includeParentEnvironment: false,
      );
      if (result.exitCode != 0) {
        expect(
          name,
          'Upload signed artifacts',
          reason: '$name: ${result.stderr}',
        );
        expect(uploadFailure, true);
        failed = true;
      }
      for (final line in commandFile.readAsLinesSync()) {
        final at = line.indexOf('=');
        if (at > 0) env[line.substring(0, at)] = line.substring(at + 1);
      }
    }
    final callbacks = File('${root.path}/callbacks.jsonl')
        .readAsLinesSync()
        .map((line) => jsonDecode(line)['status'] as String)
        .toList();
    expect(callbacks.where((s) => s != 'running').length, 1);
    if (missing != null || uploadFailure) {
      expect(executed, isNot(contains('Report success')));
      expect(callbacks, isNot(contains('succeeded')));
    }
    if (uploadFailure) {
      expect(executed, contains('Upload signed artifacts'));
      expect(File('${root.path}/curl.log').readAsStringSync(), contains('PUT'));
    }
    return callbacks;
  });
}

void main() {
  test(
    'delivered caller reusable and Dart-tool pins match exact committed bytes',
    () async {
      final caller =
          File('.github/workflows/build.yml').readAsStringSync() +
          File('.github/workflows/validate-material.yml').readAsStringSync();
      for (final match in RegExp(
        r'uses: boxliy/buildbox/\.github/workflows/(prepare|sign|finalize|validate-signing-material)\.yml@([0-9a-f]{40})',
      ).allMatches(caller)) {
        final path = '.github/workflows/${match[1]}.yml';
        final committed = await tool(['git', 'show', '${match[2]}:$path']);
        expect(
          committed,
          File(path).readAsStringSync(),
          reason: 'reusable workflow pin $path',
        );
      }
      final pins = <String>{};
      final validator =
          loadYaml(
                File(
                  '.github/workflows/validate-material.yml',
                ).readAsStringSync(),
              )
              as YamlMap;
      final validationJob = validator['jobs']['validate'];
      final validatorSha = validationJob['with']['validator_sha'] as String;
      expect(validationJob['uses'], endsWith('@$validatorSha'));
      for (final file in Directory(
        '.github/workflows',
      ).listSync().whereType<File>()) {
        pins.addAll(
          RegExp(
            r'ref: ([0-9a-f]{40})',
          ).allMatches(file.readAsStringSync()).map((match) => match[1]!),
        );
      }
      expect(
        pins.length,
        1,
        reason:
            'all trusted stage checkouts must use one exact delivered tools revision',
      );
      final paths = [
        'pubspec.yaml',
        'pubspec.lock',
        ...Directory(
          'scripts',
        ).listSync(recursive: true).whereType<File>().map((file) => file.path),
        ...Directory(
          'lib',
        ).listSync(recursive: true).whereType<File>().map((file) => file.path),
        ...Directory(
          'bin',
        ).listSync(recursive: true).whereType<File>().map((file) => file.path),
      ];
      for (final pin in pins) {
        for (final path in paths) {
          expect(
            await tool(['git', 'show', '$pin:$path']),
            File(path).readAsStringSync(),
            reason: 'trusted code pin $path',
          );
        }
      }
      for (final path in paths) {
        expect(
          await tool(['git', 'show', '$validatorSha:$path']),
          File(path).readAsStringSync(),
          reason: 'material validator code pin $path',
        );
      }
    },
  );
  test(
    'privileged jobs and artifact transport stay private, compile has no stage credential',
    () {
      for (final stage in ['prepare', 'sign', 'finalize']) {
        final workflow = File(
          '.github/workflows/$stage.yml',
        ).readAsStringSync();
        expect(
          workflow,
          isNot(contains('github.event.repository.private == true')),
        );
        final steps =
            ((loadYaml(workflow) as YamlMap)['jobs'][stage]['steps']
                as YamlList);
        final names = steps.map((s) => s['name']).toList();
        expect(
          names.indexOf('Resolve trusted Buildbox tools'),
          lessThan(
            names.indexWhere((n) => (n as String).startsWith('Exchange')),
          ),
        );
        expect(workflow, contains("flutter-version: '3.47.4'"));
        expect(workflow, isNot(contains('setup-python')));
      }
      final caller = File('.github/workflows/build.yml').readAsStringSync();
      expect(caller, contains("if: github.event_name == 'workflow_dispatch'"));
      final compile = caller.split('\n  compile:')[1].split('\n  sign:')[0];
      for (final forbidden in [
        'id-token:',
        'HAWK_STAGE_TOKEN',
        'secrets.',
        'dispatch_proof',
        'signing-material',
        'AVIARY_SOURCE_APP_PRIVATE_KEY',
      ]) {
        expect(compile, isNot(contains(forbidden)));
      }
      expect(compile, contains('persist-credentials: false'));
    },
  );
  test('failed chunk members finalize outside prepare', () {
    final caller =
        loadYaml(File('.github/workflows/build.yml').readAsStringSync())
            as YamlMap;
    final jobs = caller['jobs'] as YamlMap;
    final order = (jobs.keys.map((key) => key.toString())).toList();
    expect(
      order,
      containsAllInOrder([
        'chunk',
        'prepare',
        'compile',
        'compile-ios',
        'sign',
        'sign-ios',
        'finalize',
        'finalize-failed',
        'finalize-ios',
        'finalize-prepare',
      ]),
    );
    final prepare = jobs['prepare'] as YamlMap;
    expect(prepare['needs'], contains('chunk'));
    final prepareIf = prepare['if'] as String;
    expect(prepareIf, contains("github.event_name == 'workflow_dispatch'"));
    expect(prepareIf, contains("needs.chunk.result == 'success'"));
    expect(prepareIf, isNot(contains('always()')));
    final failed = jobs['finalize-failed'] as YamlMap;
    expect(failed['strategy']['fail-fast'], isFalse);
    expect(failed['with']['build_run_id'], r'${{ matrix.item.build_run_id }}');
    expect(failed['with']['prepare_result'], 'failure');
    expect(failed['with']['compile_result'], 'skipped');
    expect(failed['with']['sign_result'], 'skipped');
    expect(failed['with']['failure_reason'], 'prepare failed before compile');
    expect(failed['uses'], contains('/finalize.yml@'));
    expect(
      failed['strategy']['matrix']['item'],
      contains('needs.prepare.outputs.failed_matrix'),
    );
    final prepareFailure = jobs['finalize-prepare'] as YamlMap;
    expect(prepareFailure['strategy']['fail-fast'], isFalse);
    expect(
      prepareFailure['with']['build_run_id'],
      r'${{ matrix.item.build_run_id }}',
    );
    expect(
      prepareFailure['strategy']['matrix']['item'],
      contains('needs.chunk.outputs.requested_matrix'),
    );
    expect(prepareFailure['needs'], containsAll(['prepare', 'chunk']));
    expect(
      prepareFailure['with']['prepare_result'],
      r'${{ needs.prepare.result }}',
    );
    final prepareWorkflow = File(
      '.github/workflows/prepare.yml',
    ).readAsStringSync();
    expect(prepareWorkflow, isNot(contains('exchange-stage finalize')));
    expect(prepareWorkflow, isNot(contains('scripts/report-result')));
    expect(prepareWorkflow, contains('failed_matrix:'));
  });

  test('validation credential exchange is its own step', () {
    final workflow =
        loadYaml(
              File(
                '.github/workflows/validate-signing-material.yml',
              ).readAsStringSync(),
            )
            as YamlMap;
    final steps = workflow['jobs']['validate']['steps'] as YamlList;
    final names = steps
        .map((step) => (step as YamlMap)['name'] as String)
        .toList();
    final exchange = names.indexOf('Exchange validation credential');
    final validator = names.indexOf('Run signing validator');
    expect(exchange, greaterThanOrEqualTo(0));
    expect(validator, greaterThan(exchange));
    expect(
      (steps[exchange] as YamlMap)['run'],
      'scripts/signing_validation/exchange-validation',
    );
    expect(
      (steps[validator] as YamlMap)['run'],
      'scripts/signing_validation/validate-material',
    );
  });

  test('artifact scopes retention and sensitive exclusions preserved', () {
    for (final file in Directory(
      '.github/workflows',
    ).listSync().whereType<File>()) {
      final text = file.readAsStringSync();
      expect(text, isNot(contains(r'${{ inputs.dispatch_proof }}')));
      for (final step in text.split('\n      - name:').skip(1)) {
        if (step.contains('actions/upload-artifact@')) {
          expect(step, contains('retention-days: 1'));
          expect(
            RegExp(r'name: [a-z-]+-\$\{\{ github.run_id \}\}').hasMatch(step),
            true,
          );
          for (final secret in [
            'GITHUB_ENV',
            'event.json',
            'spec-response.json',
            'uploads.json',
            'sign-material-',
            'signing.keychain',
          ]) {
            expect(step, isNot(contains(secret)));
          }
        }
        if (step.contains('actions/download-artifact@')) {
          expect(step, isNot(contains('github-token:')));
          expect(step, isNot(contains('run-id:')));
          expect(step, isNot(contains('repository:')));
        }
      }
    }
  });
  test('status evaluator models implicit success and explicit failure', () {
    final inputs = {'sign_result': 'success'};
    expect(
      enabled(r"${{ inputs.sign_result == 'success' }}", inputs, true),
      false,
    );
    expect(
      enabled(
        r"${{ failure() && inputs.sign_result == 'success' }}",
        inputs,
        true,
      ),
      true,
    );
    expect(enabled(r'${{ always() }}', inputs, true), true);
  });
  test(
    'prepare failure has one terminal receipt without any artifacts',
    () async {
      expect(await execute('failure', 'skipped', 'skipped'), ['failed']);
    },
  );
  test(
    'every job cancellation preserves the existing failed terminal receipt contract',
    () async {
      for (final matrix in [
        ['cancelled', 'skipped', 'skipped'],
        ['success', 'cancelled', 'skipped'],
        ['success', 'success', 'cancelled'],
      ]) {
        expect(await execute(matrix[0], matrix[1], matrix[2]), ['failed']);
      }
    },
  );
  test('compile and sign failures never report success', () async {
    expect(await execute('success', 'failure', 'skipped'), [
      'running',
      'failed',
    ]);
    expect(await execute('success', 'success', 'failure'), [
      'running',
      'failed',
    ]);
  });
  test('missing transport failure never reports success', () async {
    for (final missing in ['Restore sign inputs', 'Restore signed outputs']) {
      expect(await execute('success', 'success', 'success', missing: missing), [
        'failed',
      ]);
    }
  });
  test(
    'upload failure emits one failed receipt, success emits verified metadata receipt',
    () async {
      expect(
        await execute('success', 'success', 'success', uploadFailure: true),
        ['running', 'failed'],
      );
      expect(await execute('success', 'success', 'success'), [
        'running',
        'succeeded',
      ]);
    },
  );
  test(
    'shell contract tests preserve dispatch isolation upload and callback semantics',
    () async {
      final result = await Process.run(
        'bash',
        ['tests/contract.sh'],
        environment: {
          ...Platform.environment,
          'BUILDBOX_TEST_DART': Platform.resolvedExecutable,
          'PROMPT_COMMAND': '',
          'BASH_ENV': '/dev/null',
        },
        includeParentEnvironment: false,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
    },
    timeout: const Timeout(Duration(minutes: 4)),
  );
}
