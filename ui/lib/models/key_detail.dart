/// Leaf-certificate metadata extracted by the backend on chain upload.
class CertificateInfo {
  const CertificateInfo({
    required this.subject,
    required this.issuer,
    required this.serialNumber,
    this.notBefore,
    this.notAfter,
  });

  factory CertificateInfo.fromJson(Map<String, dynamic> json) => CertificateInfo(
        subject: json['subject'] as String? ?? '',
        issuer: json['issuer'] as String? ?? '',
        serialNumber: json['serialNumber'] as String? ?? '',
        notBefore: _date(json['notBefore']),
        notAfter: _date(json['notAfter']),
      );

  final String subject;
  final String issuer;
  final String serialNumber;
  final DateTime? notBefore;
  final DateTime? notAfter;
}

/// Full key view. [privateKeyPem] is only ever present in the
/// `POST /api/v1/keys` (201) response.
class KeyDetail {
  const KeyDetail({
    required this.id,
    required this.name,
    required this.algorithm,
    required this.status,
    required this.fingerprintSha256,
    required this.publicKeyPem,
    required this.createdBy,
    this.certificateChainPem,
    this.certificate,
    this.compromisedReason,
    this.createdAt,
    this.updatedAt,
    this.privateKeyPem,
  });

  factory KeyDetail.fromJson(Map<String, dynamic> json) => KeyDetail(
        id: json['id'] as String? ?? '',
        name: json['name'] as String? ?? '',
        algorithm: json['algorithm'] as String? ?? '',
        status: json['status'] as String? ?? '',
        fingerprintSha256: json['fingerprintSha256'] as String? ?? '',
        publicKeyPem: json['publicKeyPem'] as String? ?? '',
        certificateChainPem: json['certificateChainPem'] as String?,
        certificate: json['certificate'] is Map<String, dynamic>
            ? CertificateInfo.fromJson(json['certificate'] as Map<String, dynamic>)
            : null,
        compromisedReason: json['compromisedReason'] as String?,
        createdBy: json['createdBy'] as String? ?? '',
        createdAt: _date(json['createdAt']),
        updatedAt: _date(json['updatedAt']),
        privateKeyPem: json['privateKeyPem'] as String?,
      );

  final String id;
  final String name;
  final String algorithm;
  final String status;
  final String fingerprintSha256;
  final String publicKeyPem;
  final String? certificateChainPem;
  final CertificateInfo? certificate;
  final String? compromisedReason;
  final String createdBy;
  final DateTime? createdAt;
  final DateTime? updatedAt;
  final String? privateKeyPem;

  static const Set<String> _operableStatuses = {'CREATED', 'READY_TO_PUBLISH', 'ACTIVE'};

  // Action gates per the SPEC §5 state machine.
  bool get canGenerateCsr => _operableStatuses.contains(status);
  bool get canUploadCertificate => status == 'CREATED' || status == 'READY_TO_PUBLISH';
  bool get canActivate => status == 'READY_TO_PUBLISH';
  bool get canCompromise => _operableStatuses.contains(status);
  bool get canDelete => _operableStatuses.contains(status);
  bool get canViewPrivateKey => _operableStatuses.contains(status);
}

DateTime? _date(dynamic value) => value is String ? DateTime.tryParse(value) : null;
