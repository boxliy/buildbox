import 'dart:io';

import 'package:buildbox_tools/src/core.dart';
import 'package:test/test.dart';

void main() {
  test(
    'discover_private_git_repos deduplicates HTTPS/SSH/.git-less boxliy deps across nested and tool pubspecs',
    () async {
      await temporary('mirrors-discover-', (dir) async {
        Directory(
          '${dir.path}/waterfowl/packages/swan_platform',
        ).createSync(recursive: true);
        Directory(
          '${dir.path}/waterfowl/apps/swan',
        ).createSync(recursive: true);
        Directory(
          '${dir.path}/waterfowl/tools/swan_build',
        ).createSync(recursive: true);
        Directory('${dir.path}/.git/hooks').createSync(recursive: true);

        File('${dir.path}/.git/pubspec.yaml').writeAsStringSync(
          'dependencies:\n  ignored:\n    git: https://github.com/boxliy/inside_git.git\n',
        );
        File('${dir.path}/waterfowl/pubspec.lock').writeAsStringSync(
          'packages:\n  nib:\n    description:\n      url: "https://github.com/boxliy/nib.git"\n',
        );
        File(
          '${dir.path}/waterfowl/packages/swan_platform/pubspec.yaml',
        ).writeAsStringSync('''
name: swan_platform
repository: https://github.com/boxliy/aviary
dependencies:
  nib_ble:
    git:
      url: https://github.com/boxliy/nib
''');
        File('${dir.path}/waterfowl/apps/swan/pubspec.yaml').writeAsStringSync(
          '''
name: swan
dependencies:
  antscan_plugin:
    git:
      url: git@github.com:boxliy/antscan
''',
        );
        File(
          '${dir.path}/waterfowl/tools/swan_build/pubspec.lock',
        ).writeAsStringSync('''
packages:
  antscan_cli:
    description:
      url: "ssh://git@github.com/boxliy/antscan.git"
  nib_cli:
    description:
      url: "git@github.com:boxliy/nib.git"
''');

        final result = await Process.run('bash', [
          '-euo',
          'pipefail',
          '-c',
          'source "${Directory.current.path}/scripts/lib/mirrors.sh" && discover_private_git_repos "${dir.path}"',
        ]);
        expect(
          result.exitCode,
          0,
          reason: '${result.stdout}\n${result.stderr}',
        );
        expect((result.stdout as String).trim().split('\n'), [
          'boxliy/antscan',
          'boxliy/nib',
        ]);
      });
    },
  );

  test(
    'build-ios configures all 6 mirror URL variants before apps/swan flutter pub get',
    () async {
      await temporary('ios-mirrors-', (dir) async {
        final bareRepo =
            '${dir.path}/source/.git/buildbox-mirrors/boxliy/antscan.git';
        final seed = Directory('${dir.path}/seed')..createSync();
        await tool(['git', '-C', seed.path, 'init', '-b', 'main', '--quiet']);
        await tool([
          'git',
          '-C',
          seed.path,
          '-c',
          'user.name=Fixture',
          '-c',
          'user.email=fixture@example.invalid',
          '-c',
          'commit.gpgsign=false',
          'commit',
          '--allow-empty',
          '--quiet',
          '-m',
          'seed',
        ]);
        final expectedSha = (await tool([
          'git',
          '-C',
          seed.path,
          'rev-parse',
          'HEAD',
        ])).trim();
        Directory(bareRepo).parent.createSync(recursive: true);
        await tool(['git', 'clone', '--bare', '--quiet', seed.path, bareRepo]);

        Directory(
          '${dir.path}/source/waterfowl/apps/swan/ios/Runner.xcodeproj',
        ).createSync(recursive: true);
        final state = Directory('${dir.path}/state')..createSync();
        writeJson('${state.path}/spec.json', {
          'config': {
            'platform': 'ios',
            'targets': ['ipa'],
            'applicationIdentifier': 'com.example.ios',
            'appDisplayName': 'iOS App',
            'frozenInputs': {'versionName': '1.0.0', 'buildNumber': 1},
          },
        });

        final workScripts = Directory('${dir.path}/scripts/lib')
          ..createSync(recursive: true);
        File(
          '${Directory.current.path}/scripts/build-ios',
        ).copySync('${dir.path}/scripts/build-ios');
        File(
          '${Directory.current.path}/scripts/lib/mirrors.sh',
        ).copySync('${workScripts.path}/mirrors.sh');
        File('${dir.path}/scripts/verify-compile-inputs')
          ..writeAsStringSync('#!/usr/bin/env bash\nexit 0\n')
          ..setLastModifiedSync(DateTime.now());
        File('${dir.path}/scripts/dart-tool').writeAsStringSync(
          '''#!/usr/bin/env bash
set -euo pipefail
if [[ "\$1" == "ios-identity" ]]; then
  : >"\$2"
  exit 0
fi
if [[ "\$1" == "ios-configure" ]]; then
  exit 0
fi
if [[ "\$1" == "ios-package" ]]; then
  printf 'ipa-bytes' >"\$3"
  exit 0
fi
exit 1
''',
        );
        await Process.run('chmod', [
          '+x',
          '${dir.path}/scripts/build-ios',
          '${dir.path}/scripts/verify-compile-inputs',
          '${dir.path}/scripts/dart-tool',
        ]);

        final bin = Directory('${dir.path}/bin')..createSync();
        File(
          '${bin.path}/uname',
        ).writeAsStringSync('#!/usr/bin/env bash\nprintf "Darwin\\n"\n');
        File(
          '${bin.path}/shasum',
        ).writeAsStringSync('#!/usr/bin/env bash\nsha256sum "\$3"\n');
        File('${bin.path}/flutter').writeAsStringSync('''#!/usr/bin/env bash
set -euo pipefail
if [[ "\$1" == "pub" && "\$2" == "get" ]]; then
  for u in \\
    "https://github.com/boxliy/antscan.git" \\
    "https://github.com/boxliy/antscan" \\
    "git@github.com:boxliy/antscan.git" \\
    "git@github.com:boxliy/antscan" \\
    "ssh://git@github.com/boxliy/antscan.git" \\
    "ssh://git@github.com/boxliy/antscan"; do
    got=\$(git ls-remote "\$u" HEAD | awk '{print \$1}')
    [[ "\$got" == "$expectedSha" ]] || exit 21
  done
  exit 0
fi
if [[ "\$1" == "build" && "\$2" == "ios" ]]; then
  mkdir -p build/ios/iphoneos
  exit 0
fi
exit 1
''');
        await Process.run('chmod', [
          '+x',
          '${bin.path}/uname',
          '${bin.path}/shasum',
          '${bin.path}/flutter',
        ]);

        final env =
            <String, String>{
                ...Platform.environment,
                'PATH': '${bin.path}:${Platform.environment['PATH']}',
                'BUILDBOX_STATE_DIR': state.path,
                'BUILDBOX_SOURCE_ROOT': '${dir.path}/source',
                'GIT_CONFIG_GLOBAL': '${dir.path}/gitconfig',
              }
              ..remove('HAWK_STAGE_TOKEN')
              ..remove('ACTIONS_ID_TOKEN_REQUEST_TOKEN');

        final result = await Process.run(
          'bash',
          ['${dir.path}/scripts/build-ios'],
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
  );
}
