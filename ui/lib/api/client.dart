import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models/audit_event.dart';
import '../models/key_detail.dart';
import '../models/key_summary.dart';

/// Error thrown for any failed API call.
///
/// [statusCode] is 0 when the backend could not be reached at all.
class ApiException implements Exception {
  ApiException(this.statusCode, this.code, this.message);

  final int statusCode;
  final String code;
  final String message;

  /// Canonical "CODE — message" presentation used across the UI.
  String get display => '$code — $message';

  @override
  String toString() => display;
}

/// Result of `GET /api/v1/keys`.
class KeyListResult {
  const KeyListResult({required this.items, required this.total});

  final List<KeySummary> items;
  final int total;
}

/// Thin HTTP client for the certificate-management API.
///
/// Holds the base URL and the bearer token in memory only. When any
/// authenticated request is rejected with 401 the token is dropped and
/// [onUnauthorized] fires once so the app can return to the connect screen.
class ApiClient {
  ApiClient({this.onUnauthorized});

  void Function()? onUnauthorized;

  String baseUrl = '';
  String backendLabel = '';
  String? _token;

  bool get isConnected => _token != null;

  /// Exchanges client credentials for a bearer token at [baseUrl].
  Future<void> connect({
    required String baseUrl,
    required String backendLabel,
    required String clientId,
    required String clientSecret,
  }) async {
    _token = null;
    this.baseUrl = baseUrl.replaceAll(RegExp(r'/+$'), '');
    this.backendLabel = backendLabel;
    final body = await _send('POST', '/api/v1/auth/token', body: {
      'clientId': clientId,
      'clientSecret': clientSecret,
    }) as Map<String, dynamic>;
    final token = body['accessToken'] as String?;
    if (token == null || token.isEmpty) {
      throw ApiException(200, 'INTERNAL', 'Token endpoint returned no access token.');
    }
    _token = token;
  }

  void disconnect() {
    _token = null;
  }

  Future<KeyListResult> listKeys({String? status}) async {
    final query = status == null ? '' : '?status=${Uri.encodeQueryComponent(status)}';
    final body = await _send('GET', '/api/v1/keys$query') as Map<String, dynamic>;
    final items = (body['items'] as List<dynamic>? ?? const <dynamic>[])
        .map((dynamic e) => KeySummary.fromJson(e as Map<String, dynamic>))
        .toList();
    return KeyListResult(items: items, total: body['total'] as int? ?? items.length);
  }

  /// Creates a key pair. The returned detail is the only response that
  /// ever carries [KeyDetail.privateKeyPem].
  Future<KeyDetail> createKey({required String name, required String algorithm}) async {
    final body = await _send('POST', '/api/v1/keys', body: {
      'name': name,
      'algorithm': algorithm,
    }) as Map<String, dynamic>;
    return KeyDetail.fromJson(body);
  }

  Future<KeyDetail> getKey(String id) async =>
      KeyDetail.fromJson(await _send('GET', '/api/v1/keys/$id') as Map<String, dynamic>);

  /// Retrieves the decrypted private key PEM. Every call is audited
  /// server-side as PRIVATE_KEY_ACCESSED.
  Future<String> fetchPrivateKey(String id) async {
    final body = await _send('GET', '/api/v1/keys/$id/private') as Map<String, dynamic>;
    return body['privateKeyPem'] as String? ?? '';
  }

  Future<String> generateCsr(
    String id, {
    required Map<String, String> subject,
    List<String> sans = const [],
  }) async {
    final body = await _send('POST', '/api/v1/keys/$id/csr', body: {
      'subject': subject,
      if (sans.isNotEmpty) 'sans': sans,
    }) as Map<String, dynamic>;
    return body['csrPem'] as String? ?? '';
  }

  Future<KeyDetail> uploadCertificate(String id, String certificateChainPem) async =>
      KeyDetail.fromJson(await _send('POST', '/api/v1/keys/$id/certificate', body: {
        'certificateChainPem': certificateChainPem,
      }) as Map<String, dynamic>);

  Future<KeyDetail> activateKey(String id) async =>
      KeyDetail.fromJson(await _send('POST', '/api/v1/keys/$id/activate') as Map<String, dynamic>);

  Future<KeyDetail> compromiseKey(String id, {String? reason}) async =>
      KeyDetail.fromJson(await _send('POST', '/api/v1/keys/$id/compromise', body: {
        if (reason != null && reason.isNotEmpty) 'reason': reason,
      }) as Map<String, dynamic>);

  Future<void> deleteKey(String id) async {
    await _send('DELETE', '/api/v1/keys/$id');
  }

  Future<List<AuditEvent>> fetchAudit(String id) async {
    final body = await _send('GET', '/api/v1/keys/$id/audit') as Map<String, dynamic>;
    return (body['items'] as List<dynamic>? ?? const <dynamic>[])
        .map((dynamic e) => AuditEvent.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Future<dynamic> _send(String method, String path, {Map<String, dynamic>? body}) async {
    final uri = Uri.parse('$baseUrl$path');
    final headers = <String, String>{
      'Content-Type': 'application/json',
      if (_token != null) 'Authorization': 'Bearer $_token',
    };
    http.Response response;
    try {
      response = switch (method) {
        'GET' => await http.get(uri, headers: headers),
        'DELETE' => await http.delete(uri, headers: headers),
        _ => await http.post(uri, headers: headers, body: jsonEncode(body ?? const <String, dynamic>{})),
      };
    } on Exception {
      throw ApiException(0, 'NETWORK', 'Could not reach $baseUrl — is the backend running?');
    }
    if (response.statusCode == 401 && _token != null) {
      _token = null;
      onUnauthorized?.call();
    }
    return _decode(response);
  }

  dynamic _decode(http.Response response) {
    if (response.statusCode >= 200 && response.statusCode < 300) {
      if (response.body.isEmpty) return null;
      return jsonDecode(response.body);
    }
    var code = 'HTTP_${response.statusCode}';
    var message = response.reasonPhrase ?? 'Request failed';
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) {
        final error = decoded['error'];
        if (error is Map<String, dynamic>) {
          code = error['code'] as String? ?? code;
          message = error['message'] as String? ?? message;
        }
      }
    } on FormatException {
      // Non-JSON error body; keep the HTTP defaults.
    }
    throw ApiException(response.statusCode, code, message);
  }
}
