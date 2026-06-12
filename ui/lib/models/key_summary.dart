/// List-item view of a key — no PEM material.
class KeySummary {
  const KeySummary({
    required this.id,
    required this.name,
    required this.algorithm,
    required this.status,
    required this.fingerprintSha256,
    required this.hasCertificate,
    this.certNotAfter,
    this.createdAt,
    this.updatedAt,
  });

  factory KeySummary.fromJson(Map<String, dynamic> json) => KeySummary(
        id: json['id'] as String? ?? '',
        name: json['name'] as String? ?? '',
        algorithm: json['algorithm'] as String? ?? '',
        status: json['status'] as String? ?? '',
        fingerprintSha256: json['fingerprintSha256'] as String? ?? '',
        hasCertificate: json['hasCertificate'] as bool? ?? false,
        certNotAfter: _date(json['certNotAfter']),
        createdAt: _date(json['createdAt']),
        updatedAt: _date(json['updatedAt']),
      );

  final String id;
  final String name;
  final String algorithm;
  final String status;
  final String fingerprintSha256;
  final bool hasCertificate;
  final DateTime? certNotAfter;
  final DateTime? createdAt;
  final DateTime? updatedAt;
}

DateTime? _date(dynamic value) => value is String ? DateTime.tryParse(value) : null;
