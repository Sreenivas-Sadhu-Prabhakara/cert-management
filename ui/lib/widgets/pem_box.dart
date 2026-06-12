import 'package:flutter/material.dart';

import '../util/format.dart';

/// Scrollable, selectable monospace block for PEM material.
class PemText extends StatelessWidget {
  const PemText(this.pem, {super.key, this.maxHeight = 280});

  final String pem;
  final double maxHeight;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      width: double.infinity,
      constraints: BoxConstraints(maxHeight: maxHeight),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest.withValues(alpha: 0.6),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: scheme.outlineVariant),
      ),
      child: SingleChildScrollView(child: SelectableText(pem, style: monoStyle)),
    );
  }
}

/// Collapsible card with a title bar, copy button and a [PemText] body.
class PemBox extends StatefulWidget {
  const PemBox({
    super.key,
    required this.title,
    required this.pem,
    this.initiallyExpanded = false,
  });

  final String title;
  final String pem;
  final bool initiallyExpanded;

  @override
  State<PemBox> createState() => _PemBoxState();
}

class _PemBoxState extends State<PemBox> {
  late bool _expanded = widget.initiallyExpanded;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      margin: EdgeInsets.zero,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: scheme.outlineVariant),
      ),
      child: Column(
        children: [
          InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () => setState(() => _expanded = !_expanded),
            child: Padding(
              padding: const EdgeInsets.fromLTRB(16, 6, 8, 6),
              child: Row(
                children: [
                  Icon(Icons.data_object, size: 18, color: scheme.primary),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(widget.title, style: Theme.of(context).textTheme.titleSmall),
                  ),
                  IconButton(
                    tooltip: 'Copy',
                    icon: const Icon(Icons.copy_all_outlined, size: 18),
                    onPressed: () => copyToClipboard(context, widget.pem),
                  ),
                  Icon(_expanded ? Icons.expand_less : Icons.expand_more,
                      color: scheme.onSurfaceVariant),
                ],
              ),
            ),
          ),
          if (_expanded)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: PemText(widget.pem),
            ),
        ],
      ),
    );
  }
}

/// Modal that displays private-key material with a security warning.
///
/// Used once right after key creation ([oneTime] = true) and for the
/// audited retrieval flow ([oneTime] = false).
Future<void> showPrivateKeyDialog(
  BuildContext context, {
  required String keyName,
  required String privateKeyPem,
  bool oneTime = false,
}) {
  return showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (dialogContext) {
      final scheme = Theme.of(dialogContext).colorScheme;
      return AlertDialog(
        title: Text('Private key — $keyName'),
        content: SizedBox(
          width: 560,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: scheme.errorContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(Icons.warning_amber_rounded, color: scheme.onErrorContainer),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        oneTime
                            ? 'Store this private key securely now. This is the only '
                                'time it is shown automatically; later retrievals are '
                                'possible but every access is recorded in the audit trail.'
                            : 'Handle this private key securely. This access has been '
                                'recorded in the audit trail.',
                        style: TextStyle(color: scheme.onErrorContainer, fontSize: 13),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 12),
              Flexible(child: PemText(privateKeyPem, maxHeight: 320)),
            ],
          ),
        ),
        actions: [
          TextButton.icon(
            onPressed: () => copyToClipboard(dialogContext, privateKeyPem),
            icon: const Icon(Icons.copy_all_outlined, size: 18),
            label: const Text('Copy'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Done'),
          ),
        ],
      );
    },
  );
}
