import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:xml/xml.dart';

typedef Json = Map<String, dynamic>;
Never fail(String message) => throw FormatException(message);
void require(bool condition, String message) {
  if (!condition) fail(message);
}

bool matches(dynamic value, String pattern) =>
    value is String && RegExp('^(?:$pattern)\$').hasMatch(value);
bool same(dynamic a, dynamic b) => canonical(a) == canonical(b);
String hashBytes(List<int> bytes) => sha256.convert(bytes).toString();
String hashJson(dynamic value) =>
    'sha256:${hashBytes(utf8.encode(canonical(value)))}';
int unicodeCompare(String a, String b) {
  final ar = a.runes.toList(), br = b.runes.toList();
  for (var i = 0; i < ar.length && i < br.length; i++) {
    final c = ar[i].compareTo(br[i]);
    if (c != 0) return c;
  }
  return ar.length.compareTo(br.length);
}

String canonical(dynamic v) {
  if (v is Map) {
    final keys = v.keys.cast<String>().toList()..sort(unicodeCompare);
    return '{${keys.map((k) => '${jsonEncode(k)}:${canonical(v[k])}').join(',')}}';
  }
  if (v is List) return '[${v.map(canonical).join(',')}]';
  if (v is double) {
    require(v.isFinite, 'nonfinite number');
    if (v == 0) return '0';
    final magnitude = v.abs();
    var encoded = magnitude < 1e-5 || magnitude >= 1e16
        ? v.toStringAsExponential()
        : jsonEncode(v);
    encoded = encoded.replaceFirstMapped(
      RegExp(r'e([+-]?)0+(\d+)'),
      (match) => 'e${match[1]}${match[2]}',
    );
    // serde_json keeps a positive exponent sign, and omits a redundant
    // decimal zero in scientific notation.
    return encoded.replaceFirst(RegExp(r'\.0e'), 'e');
  }
  return jsonEncode(v);
}

// Reject duplicate keys before jsonDecode loses evidence. Numbers preserve the
// Dart VM's signed i64 integers; canonical decimals match serde_json/Python.
dynamic strictJson(String text) {
  var i = 0;
  void ws() {
    while (i < text.length && ' \r\n\t'.contains(text[i])) {
      i++;
    }
  }

  String string() {
    final start = i++;
    var escaped = false;
    while (i < text.length) {
      final c = text[i++];
      if (!escaped && c == '"')
        return jsonDecode(text.substring(start, i)) as String;
      if (!escaped && c == '\\') {
        escaped = true;
      } else {
        escaped = false;
      }
    }
    return fail('unterminated string');
  }

  late dynamic Function() value;
  value = () {
    ws();
    require(i < text.length, 'missing value');
    final c = text[i];
    if (c == '{') {
      i++;
      ws();
      final result = <String, dynamic>{};
      if (i < text.length && text[i] == '}') {
        i++;
        return result;
      }
      while (true) {
        ws();
        require(i < text.length && text[i] == '"', 'object key');
        final key = string();
        require(!result.containsKey(key), 'duplicate JSON key');
        ws();
        require(i < text.length && text[i++] == ':', 'object colon');
        result[key] = value();
        ws();
        require(i < text.length, 'object end');
        final end = text[i++];
        if (end == '}') return result;
        require(end == ',', 'object comma');
      }
    }
    if (c == '[') {
      i++;
      ws();
      final result = <dynamic>[];
      if (i < text.length && text[i] == ']') {
        i++;
        return result;
      }
      while (true) {
        result.add(value());
        ws();
        require(i < text.length, 'array end');
        final end = text[i++];
        if (end == ']') return result;
        require(end == ',', 'array comma');
      }
    }
    if (c == '"') return string();
    final start = i;
    while (i < text.length && !(' \n\r\t,]}'.contains(text[i]))) {
      i++;
    }
    require(i > start, 'invalid token');
    final token = text.substring(start, i);
    final parsed = jsonDecode(token);
    if (parsed is num) require(parsed.isFinite, 'nonfinite number');
    if (RegExp(r'^-?[0-9]+$').hasMatch(token)) {
      require(parsed is int, 'integer exceeds signed i64 range');
    }
    return parsed;
  };
  final result = value();
  ws();
  require(i == text.length, 'trailing JSON');
  return result;
}

Json readJson(String path) => strictJson(File(path).readAsStringSync()) as Json;
void writeJson(String path, dynamic value) =>
    File(path).writeAsStringSync(canonical(value));
Future<ProcessResult> toolResult(
  List<String> args, {
  Map<String, String>? environment,
  Duration timeout = const Duration(seconds: 120),
}) async {
  require(
    args.every((s) => !s.contains('\x00') && !s.contains('\n')),
    'unsafe tool argument',
  );
  final process = await Process.start(
    args.first,
    args.skip(1).toList(),
    environment: environment,
  );
  final out = process.stdout.fold<List<int>>([], (a, b) => a..addAll(b));
  // Discard diagnostics: native tools may echo credentials or private material.
  final err = process.stderr.drain<void>();
  try {
    final code = await process.exitCode.timeout(timeout);
    await err;
    return ProcessResult(
      process.pid,
      code,
      utf8.decode(await out, allowMalformed: true),
      '',
    );
  } on TimeoutException {
    process.kill(ProcessSignal.sigkill);
    await err;
    fail('native tool timeout');
  }
}

Future<String> tool(
  List<String> args, {
  Map<String, String>? environment,
}) async {
  final result = await toolResult(args, environment: environment);
  require(result.exitCode == 0, 'native tool rejected input');
  return result.stdout as String;
}

Future<dynamic> request(String path, [dynamic body]) async {
  final base = (Platform.environment['HAWK_BASE_URL'] ?? '').replaceFirst(
    RegExp(r'/+$'),
    '',
  );
  final uri = Uri.parse('$base$path');
  require(uri.scheme == 'https' && uri.userInfo.isEmpty, 'Hawk requires HTTPS');
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 30);
  try {
    final token = Platform.environment['HAWK_STAGE_TOKEN'];
    require(token != null && token.isNotEmpty, 'missing stage credential');
    final req = await client
        .openUrl(body == null ? 'GET' : 'POST', uri)
        .timeout(const Duration(seconds: 30));
    req.followRedirects = false;
    req.headers.set('Authorization', 'Bearer $token');
    req.headers.contentType = ContentType.json;
    if (body != null) req.add(utf8.encode(canonical(body)));
    final res = await req.close().timeout(const Duration(seconds: 30));
    require(
      res.statusCode >= 200 && res.statusCode < 300,
      'platform request rejected',
    );
    final bytes = <int>[];
    await for (final chunk in res.timeout(const Duration(seconds: 30))) {
      bytes.addAll(chunk);
      require(bytes.length <= 32 * 1024 * 1024, 'platform response limit');
    }
    return bytes.isEmpty ? null : strictJson(utf8.decode(bytes));
  } finally {
    client.close(force: true);
  }
}

Future<T> temporary<T>(
  String prefix,
  Future<T> Function(Directory) action,
) async {
  final dir = await Directory.systemTemp.createTemp(prefix);
  await tool(['chmod', '700', dir.path]);
  try {
    return await action(dir);
  } finally {
    // Delete only entries created in this owned temporary directory. Never follow links.
    final entries = dir.listSync(recursive: true, followLinks: false).toList()
      ..sort((a, b) => b.path.length.compareTo(a.path.length));
    for (final entry in entries) {
      entry.deleteSync();
    }
    dir.deleteSync();
  }
}

Uint8List decodeMaterial(dynamic encoded, {int limit = 2 * 1024 * 1024}) {
  require(encoded is String, 'missing material');
  require(
    (encoded as String).length <= ((limit + 2) ~/ 3) * 4 + 4,
    'material limit',
  );
  final bytes = base64.decode(encoded);
  require(bytes.isNotEmpty && bytes.length <= limit, 'material limit');
  return bytes;
}

Future<File> privateFile(String path, List<int> bytes) async {
  final file = File(path);
  file.writeAsBytesSync(bytes);
  await tool(['chmod', '600', path]);
  return file;
}

dynamic parsePlist(String text) {
  final document = XmlDocument.parse(text);
  final root = document.rootElement;
  final node = root.name.local == 'plist' ? root.childElements.single : root;
  dynamic parse(XmlElement e) {
    switch (e.name.local) {
      case 'dict':
        final nodes = e.childElements.toList();
        require(nodes.length.isEven, 'invalid plist dictionary');
        final result = <String, dynamic>{};
        for (var i = 0; i < nodes.length; i += 2) {
          require(
            nodes[i].name.local == 'key' &&
                !result.containsKey(nodes[i].innerText),
            'invalid plist key',
          );
          result[nodes[i].innerText] = parse(nodes[i + 1]);
        }
        return result;
      case 'array':
        return e.childElements.map(parse).toList();
      case 'string':
      case 'key':
        return e.innerText;
      case 'integer':
        return int.parse(e.innerText);
      case 'real':
        return double.parse(e.innerText);
      case 'true':
        return true;
      case 'false':
        return false;
      case 'data':
        return base64.decode(e.innerText.replaceAll(RegExp(r'\s'), ''));
      case 'date':
        return DateTime.parse(e.innerText).toUtc();
      default:
        return fail('unsupported plist value');
    }
  }

  return parse(node);
}

String encodePlist(dynamic value) {
  XmlElement element(dynamic v) {
    if (v is Map)
      return XmlElement(XmlName('dict'), [], [
        for (final e in v.entries) ...[
          XmlElement(XmlName('key'), [], [XmlText(e.key as String)]),
          element(e.value),
        ],
      ]);
    if (v is Uint8List)
      return XmlElement(XmlName('data'), [], [XmlText(base64.encode(v))]);
    if (v is DateTime)
      return XmlElement(XmlName('date'), [], [
        XmlText(v.toUtc().toIso8601String()),
      ]);
    if (v is List) return XmlElement(XmlName('array'), [], v.map(element));
    if (v is bool) return XmlElement(XmlName(v ? 'true' : 'false'));
    return XmlElement(
      XmlName(
        v is int
            ? 'integer'
            : v is double
            ? 'real'
            : 'string',
      ),
      [],
      [XmlText('$v')],
    );
  }

  return '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">${XmlElement(XmlName('plist'), [XmlAttribute(XmlName('version'), '1.0')], [element(value)])}';
}

Future<Json> readPlist(String path) async {
  final bytes = File(path).readAsBytesSync();
  if (utf8.decode(bytes.take(6).toList(), allowMalformed: true) == 'bplist') {
    return parsePlist(
          await tool(['plutil', '-convert', 'xml1', '-o', '-', path]),
        )
        as Json;
  }
  return parsePlist(utf8.decode(bytes)) as Json;
}
