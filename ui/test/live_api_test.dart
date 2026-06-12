// Live integration test: drives the real ApiClient against running backends.
// Skipped unless CERTMGR_LIVE=1 (backends 8081-8084 up, .env sourced):
//   set -a; source ../.env; set +a; CERTMGR_LIVE=1 flutter test test/live_api_test.dart
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:cert_manager_ui/api/client.dart';

void main() {
  final live = Platform.environment['CERTMGR_LIVE'] == '1';
  final clientId = Platform.environment['AUTH_CLIENT_ID'] ?? 'admin';
  final clientSecret = Platform.environment['AUTH_CLIENT_SECRET'] ?? '';

  const backends = {
    'java': 'http://localhost:8081',
    'go': 'http://localhost:8082',
    'node': 'http://localhost:8083',
    'rust': 'http://localhost:8084',
  };

  for (final entry in backends.entries) {
    test('full client flow against ${entry.key} backend', () async {
      final api = ApiClient();
      await api.connect(
        baseUrl: entry.value,
        backendLabel: entry.key,
        clientId: clientId,
        clientSecret: clientSecret,
      );
      expect(api.isConnected, isTrue);

      final created = await api.createKey(
          name: 'ui-live-${entry.key}', algorithm: 'EC_P256');
      expect(created.status, 'CREATED');
      expect(created.privateKeyPem, contains('BEGIN PRIVATE KEY'));
      expect(created.fingerprintSha256, hasLength(64));

      final detail = await api.getKey(created.id);
      expect(detail.privateKeyPem, isNull);
      expect(detail.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(detail.createdAt, isNotNull);

      final csr = await api.generateCsr(created.id,
          subject: {'commonName': 'ui.example.test'},
          sans: ['ui.example.test']);
      expect(csr, contains('BEGIN CERTIFICATE REQUEST'));

      final list = await api.listKeys(status: 'CREATED');
      expect(list.items.map((k) => k.id), contains(created.id));

      // illegal transition surfaces the spec error envelope
      await expectLater(
        api.activateKey(created.id),
        throwsA(isA<ApiException>()
            .having((e) => e.code, 'code', 'INVALID_STATE')),
      );

      final audit = await api.fetchAudit(created.id);
      expect(audit.map((e) => e.eventType),
          containsAll(['KEY_GENERATED', 'CSR_ISSUED']));
      expect(audit.first.backend, entry.key);

      await api.deleteKey(created.id);
      final deleted = await api.getKey(created.id);
      expect(deleted.status, 'DELETED');
    }, skip: live ? false : 'CERTMGR_LIVE != 1');
  }
}
