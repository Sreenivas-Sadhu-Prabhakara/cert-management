/// One row of a key's append-only audit trail.
class AuditEvent {
  const AuditEvent({
    required this.id,
    required this.keyId,
    required this.eventType,
    required this.actor,
    required this.backend,
    this.detail,
    this.occurredAt,
  });

  factory AuditEvent.fromJson(Map<String, dynamic> json) => AuditEvent(
        id: (json['id'] as num?)?.toInt() ?? 0,
        keyId: json['keyId'] as String? ?? '',
        eventType: json['eventType'] as String? ?? '',
        actor: json['actor'] as String? ?? '',
        backend: json['backend'] as String? ?? '',
        detail: json['detail'] is Map<String, dynamic>
            ? json['detail'] as Map<String, dynamic>
            : null,
        occurredAt: _date(json['occurredAt']),
      );

  final int id;
  final String keyId;
  final String eventType;
  final String actor;
  final String backend;
  final Map<String, dynamic>? detail;
  final DateTime? occurredAt;
}

DateTime? _date(dynamic value) => value is String ? DateTime.tryParse(value) : null;
