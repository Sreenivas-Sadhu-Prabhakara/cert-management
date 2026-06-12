import 'dart:convert';

import 'package:flutter/material.dart';

import '../api/client.dart';
import '../models/audit_event.dart';
import '../models/key_detail.dart';
import '../util/format.dart';
import '../widgets/pem_box.dart';
import '../widgets/status_chip.dart';

/// Detail view of a single key.
///
/// Two tabs: Overview (metadata, PEM material, lifecycle actions gated by
/// the SPEC §5 state machine) and Audit (append-only event timeline).
class KeyDetailScreen extends StatefulWidget {
  const KeyDetailScreen({
    super.key,
    required this.client,
    required this.keyId,
    this.initialName,
  });

  final ApiClient client;
  final String keyId;

  /// Name shown in the AppBar until the detail loads.
  final String? initialName;

  @override
  State<KeyDetailScreen> createState() => _KeyDetailScreenState();
}

class _KeyDetailScreenState extends State<KeyDetailScreen> {
  KeyDetail? _detail;
  bool _loadingDetail = true;
  String? _detailError;

  List<AuditEvent> _audit = const [];
  bool _loadingAudit = true;
  String? _auditError;

  @override
  void initState() {
    super.initState();
    _loadDetail();
    _loadAudit();
  }

  Future<void> _loadDetail() async {
    try {
      final detail = await widget.client.getKey(widget.keyId);
      if (!mounted) return;
      setState(() {
        _detail = detail;
        _loadingDetail = false;
        _detailError = null;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loadingDetail = false;
        _detailError = describeError(e);
      });
    }
  }

  Future<void> _loadAudit() async {
    try {
      final events = await widget.client.fetchAudit(widget.keyId);
      if (!mounted) return;
      setState(() {
        _audit = events;
        _loadingAudit = false;
        _auditError = null;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loadingAudit = false;
        _auditError = describeError(e);
      });
    }
  }

  void _refresh() {
    setState(() {
      _loadingDetail = true;
      _detailError = null;
      _loadingAudit = true;
      _auditError = null;
    });
    _loadDetail();
    _loadAudit();
  }

  /// Applies a server-returned [KeyDetail] after a successful action and
  /// refreshes the audit trail (every action writes an event).
  void _applyDetail(KeyDetail detail, String message) {
    setState(() => _detail = detail);
    showSnack(context, message);
    _loadAudit();
  }

  // ----- Actions -------------------------------------------------------

  Future<void> _generateCsr() async {
    final csrPem = await showDialog<String>(
      context: context,
      builder: (_) => _CsrDialog(client: widget.client, keyId: widget.keyId),
    );
    if (csrPem == null || csrPem.isEmpty || !mounted) return;
    _loadAudit();
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Certificate signing request'),
        content: SizedBox(
          width: 560,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Send this CSR to your certificate authority. It is not stored '
                'by the service; the requested subject was recorded in the '
                'audit trail.',
                style: Theme.of(dialogContext).textTheme.bodySmall,
              ),
              const SizedBox(height: 12),
              Flexible(child: PemText(csrPem, maxHeight: 320)),
            ],
          ),
        ),
        actions: [
          TextButton.icon(
            onPressed: () => copyToClipboard(dialogContext, csrPem),
            icon: const Icon(Icons.copy_all_outlined, size: 18),
            label: const Text('Copy'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Done'),
          ),
        ],
      ),
    );
  }

  Future<void> _uploadCertificate() async {
    final updated = await showDialog<KeyDetail>(
      context: context,
      builder: (_) =>
          _UploadChainDialog(client: widget.client, keyId: widget.keyId),
    );
    if (updated == null || !mounted) return;
    _applyDetail(
        updated, 'Certificate chain verified — status ${updated.status}.');
  }

  Future<void> _activate() async {
    try {
      final updated = await widget.client.activateKey(widget.keyId);
      if (!mounted) return;
      _applyDetail(updated, 'Key activated.');
    } catch (e) {
      if (mounted) showErrorSnack(context, e);
    }
  }

  Future<void> _compromise() async {
    final updated = await showDialog<KeyDetail>(
      context: context,
      builder: (_) =>
          _CompromiseDialog(client: widget.client, keyId: widget.keyId),
    );
    if (updated == null || !mounted) return;
    _applyDetail(updated, 'Key marked compromised — this state is terminal.');
  }

  Future<void> _delete() async {
    final deleted = await showDialog<bool>(
      context: context,
      builder: (_) => _DeleteDialog(client: widget.client, keyId: widget.keyId),
    );
    if (deleted != true || !mounted) return;
    showSnack(context, 'Key deleted — private key material crypto-shredded.');
    _refresh();
  }

  Future<void> _viewPrivateKey() async {
    final scheme = Theme.of(context).colorScheme;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        icon: Icon(Icons.lock_open_outlined, color: scheme.error),
        title: const Text('Retrieve private key?'),
        content: const SizedBox(
          width: 420,
          child: Text(
            'This will decrypt and display the private key. The access is '
            'recorded permanently in the append-only audit trail as '
            'PRIVATE_KEY_ACCESSED.',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Retrieve'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    final String pem;
    try {
      pem = await widget.client.fetchPrivateKey(widget.keyId);
    } catch (e) {
      if (mounted) showErrorSnack(context, e);
      return;
    }
    if (!mounted) return;
    _loadAudit();
    await showPrivateKeyDialog(
      context,
      keyName: _detail?.name ?? widget.initialName ?? widget.keyId,
      privateKeyPem: pem,
    );
  }

  // ----- Build ----------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final title = _detail?.name ?? widget.initialName ?? 'Key';
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          title: Text(title, overflow: TextOverflow.ellipsis),
          actions: [
            IconButton(
              tooltip: 'Refresh',
              icon: const Icon(Icons.refresh),
              onPressed: _refresh,
            ),
          ],
          bottom: const TabBar(
            tabs: [
              Tab(icon: Icon(Icons.info_outline), text: 'Overview'),
              Tab(icon: Icon(Icons.history), text: 'Audit'),
            ],
          ),
        ),
        body: TabBarView(
          children: [_buildOverview(), _buildAudit()],
        ),
      ),
    );
  }

  Widget _buildOverview() {
    if (_loadingDetail) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_detailError != null) {
      return _ErrorPane(message: _detailError!, onRetry: _refresh);
    }
    final detail = _detail!;
    final hasChain = detail.certificateChainPem?.trim().isNotEmpty ?? false;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 860),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildMetadataCard(detail),
              const SizedBox(height: 12),
              PemBox(title: 'Public key (PEM)', pem: detail.publicKeyPem),
              const SizedBox(height: 12),
              if (detail.certificate != null || hasChain)
                _buildCertificateCard(detail)
              else
                _buildNoCertificateHint(detail),
              const SizedBox(height: 12),
              _buildActionsCard(detail),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildMetadataCard(KeyDetail detail) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    detail.name,
                    style: theme.textTheme.titleLarge,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(width: 12),
                StatusChip(detail.status),
              ],
            ),
            const SizedBox(height: 14),
            _MetaRow(
              'Key ID',
              SelectableText(detail.id,
                  style: monoStyle.copyWith(fontSize: 12.5)),
            ),
            _MetaRow('Algorithm', Text(detail.algorithm)),
            _MetaRow(
              'Fingerprint (SHA-256)',
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: SelectableText(
                      detail.fingerprintSha256,
                      style: monoStyle.copyWith(fontSize: 12.5),
                    ),
                  ),
                  IconButton(
                    tooltip: 'Copy fingerprint',
                    visualDensity: VisualDensity.compact,
                    icon: const Icon(Icons.copy_all_outlined, size: 16),
                    onPressed: () =>
                        copyToClipboard(context, detail.fingerprintSha256),
                  ),
                ],
              ),
            ),
            _MetaRow('Created', Text(formatTimestamp(detail.createdAt))),
            _MetaRow('Updated', Text(formatTimestamp(detail.updatedAt))),
            _MetaRow('Created by', Text(detail.createdBy)),
            if (detail.compromisedReason != null &&
                detail.compromisedReason!.isNotEmpty)
              _MetaRow(
                'Compromised reason',
                Text(
                  detail.compromisedReason!,
                  style: TextStyle(color: scheme.error),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildCertificateCard(KeyDetail detail) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final cert = detail.certificate;
    final chain = detail.certificateChainPem;
    final expired = cert?.notAfter != null &&
        cert!.notAfter!.isBefore(DateTime.now().toUtc());
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.verified_outlined, size: 20, color: scheme.primary),
                const SizedBox(width: 8),
                Text('Certificate', style: theme.textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 12),
            if (cert != null) ...[
              _MetaRow('Subject', SelectableText(cert.subject)),
              _MetaRow('Issuer', SelectableText(cert.issuer)),
              _MetaRow(
                'Serial number',
                SelectableText(cert.serialNumber,
                    style: monoStyle.copyWith(fontSize: 12.5)),
              ),
              _MetaRow('Not before', Text(formatTimestamp(cert.notBefore))),
              _MetaRow(
                'Not after',
                Text(
                  formatTimestamp(cert.notAfter) + (expired ? '  (expired)' : ''),
                  style: expired ? TextStyle(color: scheme.error) : null,
                ),
              ),
            ],
            if (chain != null && chain.trim().isNotEmpty) ...[
              const SizedBox(height: 12),
              PemBox(title: 'Certificate chain (PEM)', pem: chain),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildNoCertificateHint(KeyDetail detail) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Card(
      margin: EdgeInsets.zero,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: scheme.outlineVariant),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(Icons.workspace_premium_outlined,
                color: scheme.onSurfaceVariant),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                detail.canUploadCertificate
                    ? 'No certificate yet. Generate a CSR, have your '
                        'certificate authority sign it, then upload the chain '
                        '(leaf first) — it is verified before being stored.'
                    : 'No certificate is stored for this key.',
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildActionsCard(KeyDetail detail) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final terminal =
        detail.status == 'COMPROMISED' || detail.status == 'DELETED';
    final destructiveStyle =
        OutlinedButton.styleFrom(foregroundColor: scheme.error);
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Actions', style: theme.textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(
              'Only operations legal for status ${detail.status} are enabled.',
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 14),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                FilledButton.tonalIcon(
                  onPressed: detail.canGenerateCsr ? _generateCsr : null,
                  icon: const Icon(Icons.edit_document, size: 18),
                  label: const Text('Generate CSR'),
                ),
                FilledButton.tonalIcon(
                  onPressed:
                      detail.canUploadCertificate ? _uploadCertificate : null,
                  icon: const Icon(Icons.upload_file_outlined, size: 18),
                  label: const Text('Upload certificate chain'),
                ),
                FilledButton.icon(
                  onPressed: detail.canActivate ? _activate : null,
                  icon: const Icon(Icons.check_circle_outline, size: 18),
                  label: const Text('Activate'),
                ),
                OutlinedButton.icon(
                  onPressed: detail.canViewPrivateKey ? _viewPrivateKey : null,
                  icon: const Icon(Icons.lock_open_outlined, size: 18),
                  label: const Text('View private key'),
                ),
                OutlinedButton.icon(
                  onPressed: detail.canCompromise ? _compromise : null,
                  style: destructiveStyle,
                  icon: const Icon(Icons.warning_amber_rounded, size: 18),
                  label: const Text('Mark compromised'),
                ),
                OutlinedButton.icon(
                  onPressed: detail.canDelete ? _delete : null,
                  style: destructiveStyle,
                  icon: const Icon(Icons.delete_outline, size: 18),
                  label: const Text('Delete'),
                ),
              ],
            ),
            if (terminal) ...[
              const SizedBox(height: 14),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.lock_outline, size: 16, color: scheme.error),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      detail.status == 'DELETED'
                          ? 'This key was soft-deleted: the private key was '
                              'crypto-shredded and is unrecoverable; the record '
                              'and audit trail remain for inventory.'
                          : 'COMPROMISED is terminal: the record is preserved '
                              'as incident evidence and cannot be deleted, '
                              'reactivated, or have its private key retrieved.',
                      style:
                          theme.textTheme.bodySmall?.copyWith(color: scheme.error),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildAudit() {
    if (_loadingAudit) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_auditError != null) {
      return _ErrorPane(
        message: _auditError!,
        onRetry: () {
          setState(() {
            _loadingAudit = true;
            _auditError = null;
          });
          _loadAudit();
        },
      );
    }
    if (_audit.isEmpty) {
      return Center(
        child: Text(
          'No audit events.',
          style: TextStyle(color: Theme.of(context).colorScheme.onSurfaceVariant),
        ),
      );
    }
    return RefreshIndicator(
      onRefresh: _loadAudit,
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 860),
          child: ListView.builder(
            physics: const AlwaysScrollableScrollPhysics(),
            padding: const EdgeInsets.all(16),
            itemCount: _audit.length,
            itemBuilder: (context, index) => _AuditTile(
              event: _audit[index],
              isLast: index == _audit.length - 1,
            ),
          ),
        ),
      ),
    );
  }
}

/// Label/value row used in metadata cards.
class _MetaRow extends StatelessWidget {
  const _MetaRow(this.label, this.value);

  final String label;
  final Widget value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 170,
            child: Text(
              label,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(child: value),
        ],
      ),
    );
  }
}

class _ErrorPane extends StatelessWidget {
  const _ErrorPane({required this.message, required this.onRetry});

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, size: 40, color: scheme.error),
            const SizedBox(height: 12),
            Text(message, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            FilledButton.tonal(onPressed: onRetry, child: const Text('Retry')),
          ],
        ),
      ),
    );
  }
}

/// One event in the audit timeline.
class _AuditTile extends StatelessWidget {
  const _AuditTile({required this.event, required this.isLast});

  final AuditEvent event;
  final bool isLast;

  static (IconData, String) _styleFor(String eventType) {
    switch (eventType) {
      case 'KEY_GENERATED':
        return (Icons.vpn_key_outlined, 'CREATED');
      case 'CSR_ISSUED':
        return (Icons.edit_document, 'CREATED');
      case 'CERTIFICATE_UPLOADED':
        return (Icons.verified_outlined, 'READY_TO_PUBLISH');
      case 'CERTIFICATE_REJECTED':
        return (Icons.gpp_bad_outlined, 'COMPROMISED');
      case 'ACTIVATED':
        return (Icons.check_circle_outline, 'ACTIVE');
      case 'COMPROMISED':
        return (Icons.warning_amber_rounded, 'COMPROMISED');
      case 'DELETED':
        return (Icons.delete_outline, 'DELETED');
      case 'PRIVATE_KEY_ACCESSED':
        return (Icons.lock_open_outlined, 'READY_TO_PUBLISH');
      default:
        return (Icons.circle_outlined, 'DELETED');
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final (icon, colorKey) = _styleFor(event.eventType);
    final color = statusColor(colorKey, theme.brightness);
    final detail = event.detail;
    return IntrinsicHeight(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Column(
            children: [
              Container(
                width: 34,
                height: 34,
                decoration: BoxDecoration(
                  color: color.withValues(alpha: 0.14),
                  shape: BoxShape.circle,
                  border: Border.all(color: color.withValues(alpha: 0.45)),
                ),
                child: Icon(icon, size: 17, color: color),
              ),
              if (!isLast)
                Expanded(
                  child: Container(width: 2, color: scheme.outlineVariant),
                ),
            ],
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Padding(
              padding: EdgeInsets.only(bottom: isLast ? 0 : 20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Wrap(
                    spacing: 8,
                    runSpacing: 4,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      Text(
                        event.eventType,
                        style: theme.textTheme.titleSmall,
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: scheme.secondaryContainer,
                          borderRadius: BorderRadius.circular(999),
                        ),
                        child: Text(
                          event.backend,
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            color: scheme.onSecondaryContainer,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(
                    'by ${event.actor} · ${formatTimestamp(event.occurredAt)}',
                    style: theme.textTheme.bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                  if (detail != null && detail.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 6),
                      child: Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: scheme.surfaceContainerHighest
                              .withValues(alpha: 0.5),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: SelectableText(
                          const JsonEncoder.withIndent('  ').convert(detail),
                          style: monoStyle.copyWith(fontSize: 11, height: 1.4),
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// CSR subject/SANs form. Pops with the generated `csrPem` on success.
class _CsrDialog extends StatefulWidget {
  const _CsrDialog({required this.client, required this.keyId});

  final ApiClient client;
  final String keyId;

  @override
  State<_CsrDialog> createState() => _CsrDialogState();
}

class _CsrDialogState extends State<_CsrDialog> {
  final _commonName = TextEditingController();
  final _organization = TextEditingController();
  final _organizationalUnit = TextEditingController();
  final _country = TextEditingController();
  final _state = TextEditingController();
  final _locality = TextEditingController();
  final _sans = TextEditingController();
  bool _submitting = false;
  String? _error;

  @override
  void dispose() {
    _commonName.dispose();
    _organization.dispose();
    _organizationalUnit.dispose();
    _country.dispose();
    _state.dispose();
    _locality.dispose();
    _sans.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final cn = _commonName.text.trim();
    if (cn.isEmpty) {
      setState(() => _error = 'INVALID_REQUEST — common name is required');
      return;
    }
    setState(() {
      _submitting = true;
      _error = null;
    });
    final subject = <String, String>{
      'commonName': cn,
      if (_organization.text.trim().isNotEmpty)
        'organization': _organization.text.trim(),
      if (_organizationalUnit.text.trim().isNotEmpty)
        'organizationalUnit': _organizationalUnit.text.trim(),
      if (_country.text.trim().isNotEmpty) 'country': _country.text.trim(),
      if (_state.text.trim().isNotEmpty) 'state': _state.text.trim(),
      if (_locality.text.trim().isNotEmpty) 'locality': _locality.text.trim(),
    };
    final sans = _sans.text
        .split(',')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    try {
      final csrPem = await widget.client
          .generateCsr(widget.keyId, subject: subject, sans: sans);
      if (mounted) Navigator.of(context).pop(csrPem);
    } catch (e) {
      if (mounted) setState(() => _error = describeError(e));
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return AlertDialog(
      title: const Text('Generate CSR'),
      content: SizedBox(
        width: 480,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _commonName,
                autofocus: true,
                decoration: const InputDecoration(
                  labelText: 'Common name *',
                  hintText: 'www.example.test',
                ),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _organization,
                      decoration:
                          const InputDecoration(labelText: 'Organization'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: TextField(
                      controller: _organizationalUnit,
                      decoration: const InputDecoration(
                          labelText: 'Organizational unit'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _country,
                      decoration: const InputDecoration(
                        labelText: 'Country',
                        hintText: 'US',
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: TextField(
                      controller: _state,
                      decoration:
                          const InputDecoration(labelText: 'State/province'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: TextField(
                      controller: _locality,
                      decoration: const InputDecoration(labelText: 'Locality'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _sans,
                decoration: const InputDecoration(
                  labelText: 'Subject alternative names',
                  hintText: 'www.example.test, example.test',
                  helperText: 'Comma-separated DNS names (optional)',
                ),
              ),
              if (_error != null) ...[
                const SizedBox(height: 14),
                _InlineError(_error!, scheme: scheme),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _submitting ? null : _submit,
          child: _submitting
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Generate CSR'),
        ),
      ],
    );
  }
}

/// Certificate-chain paste dialog. Pops with the updated [KeyDetail] on
/// success; 422 verification failures (KEY_MISMATCH / CHAIN_BROKEN /
/// CERT_NOT_VALID) are surfaced inline as "CODE — message".
class _UploadChainDialog extends StatefulWidget {
  const _UploadChainDialog({required this.client, required this.keyId});

  final ApiClient client;
  final String keyId;

  @override
  State<_UploadChainDialog> createState() => _UploadChainDialogState();
}

class _UploadChainDialogState extends State<_UploadChainDialog> {
  final _chain = TextEditingController();
  bool _submitting = false;
  String? _error;

  @override
  void dispose() {
    _chain.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final pem = _chain.text.trim();
    if (pem.isEmpty) {
      setState(
          () => _error = 'INVALID_REQUEST — paste a PEM certificate chain');
      return;
    }
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final detail = await widget.client.uploadCertificate(widget.keyId, pem);
      if (mounted) Navigator.of(context).pop(detail);
    } catch (e) {
      if (mounted) setState(() => _error = describeError(e));
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return AlertDialog(
      title: const Text('Upload certificate chain'),
      content: SizedBox(
        width: 560,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Paste one or more PEM certificate blocks, leaf first, then '
              'intermediates (root optional). The chain is verified against '
              'the stored public key before being accepted.',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _chain,
              autofocus: true,
              maxLines: 12,
              style: monoStyle,
              decoration: const InputDecoration(
                hintText: '-----BEGIN CERTIFICATE-----\n…',
                alignLabelWithHint: true,
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 14),
              _InlineError(_error!, scheme: scheme),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _submitting ? null : _submit,
          child: _submitting
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Verify & upload'),
        ),
      ],
    );
  }
}

/// Destructive confirmation for marking a key compromised, with an optional
/// reason. Pops with the updated [KeyDetail] on success.
class _CompromiseDialog extends StatefulWidget {
  const _CompromiseDialog({required this.client, required this.keyId});

  final ApiClient client;
  final String keyId;

  @override
  State<_CompromiseDialog> createState() => _CompromiseDialogState();
}

class _CompromiseDialogState extends State<_CompromiseDialog> {
  final _reason = TextEditingController();
  bool _submitting = false;
  String? _error;

  @override
  void dispose() {
    _reason.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final detail = await widget.client
          .compromiseKey(widget.keyId, reason: _reason.text.trim());
      if (mounted) Navigator.of(context).pop(detail);
    } catch (e) {
      if (mounted) setState(() => _error = describeError(e));
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return AlertDialog(
      icon: Icon(Icons.warning_amber_rounded, color: scheme.error),
      title: const Text('Mark key as compromised?'),
      content: SizedBox(
        width: 440,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'This is irreversible. A compromised key cannot be reactivated '
              'or deleted, and its private key can no longer be retrieved. '
              'The record is frozen as incident evidence.',
            ),
            const SizedBox(height: 14),
            TextField(
              controller: _reason,
              maxLines: 2,
              decoration: const InputDecoration(
                labelText: 'Reason (optional)',
                hintText: 'e.g. leaked in CI logs',
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 14),
              _InlineError(_error!, scheme: scheme),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _submitting ? null : _submit,
          style: FilledButton.styleFrom(
            backgroundColor: scheme.error,
            foregroundColor: scheme.onError,
          ),
          child: _submitting
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Mark compromised'),
        ),
      ],
    );
  }
}

/// Destructive confirmation for soft delete. Pops `true` on success.
class _DeleteDialog extends StatefulWidget {
  const _DeleteDialog({required this.client, required this.keyId});

  final ApiClient client;
  final String keyId;

  @override
  State<_DeleteDialog> createState() => _DeleteDialogState();
}

class _DeleteDialogState extends State<_DeleteDialog> {
  bool _submitting = false;
  String? _error;

  Future<void> _submit() async {
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      await widget.client.deleteKey(widget.keyId);
      if (mounted) Navigator.of(context).pop(true);
    } catch (e) {
      if (mounted) setState(() => _error = describeError(e));
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return AlertDialog(
      icon: Icon(Icons.delete_outline, color: scheme.error),
      title: const Text('Delete this key?'),
      content: SizedBox(
        width: 440,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Deletion is soft: the encrypted private key is destroyed '
              'immediately (crypto-shredded) and cannot be recovered, while '
              'the record — name, fingerprint, certificate metadata and the '
              'full audit history — is kept for inventory and forensics. '
              'This cannot be undone.',
            ),
            if (_error != null) ...[
              const SizedBox(height: 14),
              _InlineError(_error!, scheme: scheme),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _submitting ? null : _submit,
          style: FilledButton.styleFrom(
            backgroundColor: scheme.error,
            foregroundColor: scheme.onError,
          ),
          child: _submitting
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Delete key'),
        ),
      ],
    );
  }
}

/// Inline "CODE — message" error container used inside dialogs.
class _InlineError extends StatelessWidget {
  const _InlineError(this.message, {required this.scheme});

  final String message;
  final ColorScheme scheme;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: scheme.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        message,
        style: TextStyle(color: scheme.onErrorContainer, fontSize: 13),
      ),
    );
  }
}
