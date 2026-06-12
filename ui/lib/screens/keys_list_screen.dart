import 'package:flutter/material.dart';

import '../api/client.dart';
import '../models/key_detail.dart';
import '../models/key_summary.dart';
import '../util/format.dart';
import '../widgets/pem_box.dart';
import '../widgets/status_chip.dart';
import 'connect_screen.dart';
import 'docs_screen.dart';
import 'key_detail_screen.dart';

const List<String> kAlgorithms = [
  'RSA_2048',
  'RSA_3072',
  'RSA_4096',
  'EC_P256',
  'EC_P384',
];

const List<String?> _statusFilters = [
  null,
  'CREATED',
  'READY_TO_PUBLISH',
  'ACTIVE',
  'COMPROMISED',
  'DELETED',
];

/// Main screen: filterable key list plus key generation.
class KeysListScreen extends StatefulWidget {
  const KeysListScreen({super.key, required this.client});

  final ApiClient client;

  @override
  State<KeysListScreen> createState() => _KeysListScreenState();
}

class _KeysListScreenState extends State<KeysListScreen> {
  String? _statusFilter;
  bool _loading = true;
  String? _error;
  List<KeySummary> _keys = const [];
  int _total = 0;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final result = await widget.client.listKeys(status: _statusFilter);
      if (!mounted) return;
      setState(() {
        _keys = result.items;
        _total = result.total;
        _loading = false;
        _error = null;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = describeError(e);
      });
    }
  }

  void _reload() {
    setState(() {
      _loading = true;
      _error = null;
    });
    _load();
  }

  void _setFilter(String? status) {
    setState(() {
      _statusFilter = status;
      _loading = true;
      _error = null;
    });
    _load();
  }

  void _disconnect() {
    widget.client.disconnect();
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute<void>(
        builder: (_) => ConnectScreen(client: widget.client),
      ),
      (route) => false,
    );
  }

  Future<void> _openDetail(KeySummary key) async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => KeyDetailScreen(
          client: widget.client,
          keyId: key.id,
          initialName: key.name,
        ),
      ),
    );
    if (mounted) _load();
  }

  Future<void> _generateKey() async {
    final created = await showDialog<KeyDetail>(
      context: context,
      builder: (_) => _GenerateKeyDialog(client: widget.client),
    );
    if (created == null || !mounted) return;
    final privatePem = created.privateKeyPem;
    if (privatePem != null && privatePem.isNotEmpty) {
      await showPrivateKeyDialog(
        context,
        keyName: created.name,
        privateKeyPem: privatePem,
        oneTime: true,
      );
    }
    if (mounted) _reload();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            const Text('Keys'),
            const SizedBox(width: 12),
            Tooltip(
              message: widget.client.baseUrl,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: scheme.secondaryContainer,
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.dns_outlined,
                        size: 14, color: scheme.onSecondaryContainer),
                    const SizedBox(width: 6),
                    Text(
                      widget.client.backendLabel,
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: scheme.onSecondaryContainer,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Documentation',
            icon: const Icon(Icons.menu_book_outlined),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute<void>(builder: (_) => const DocsScreen()),
            ),
          ),
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh),
            onPressed: _reload,
          ),
          IconButton(
            tooltip: 'Disconnect',
            icon: const Icon(Icons.logout),
            onPressed: _disconnect,
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _generateKey,
        icon: const Icon(Icons.add),
        label: const Text('Generate key'),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(
                children: [
                  for (final status in _statusFilters)
                    Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: ChoiceChip(
                        label: Text(status ?? 'All'),
                        selected: _statusFilter == status,
                        onSelected: (_) => _setFilter(status),
                      ),
                    ),
                ],
              ),
            ),
          ),
          Expanded(child: _buildBody()),
        ],
      ),
    );
  }

  Widget _buildBody() {
    final scheme = Theme.of(context).colorScheme;
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.cloud_off_outlined, size: 40, color: scheme.error),
            const SizedBox(height: 12),
            Text(_error!, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            FilledButton.tonal(onPressed: _reload, child: const Text('Retry')),
          ],
        ),
      );
    }
    if (_keys.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.key_off_outlined,
                size: 40, color: scheme.onSurfaceVariant),
            const SizedBox(height: 12),
            Text(
              _statusFilter == null
                  ? 'No keys yet — generate the first one.'
                  : 'No keys with status $_statusFilter.',
              style: TextStyle(color: scheme.onSurfaceVariant),
            ),
          ],
        ),
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 900),
          child: Column(
            children: [
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 4),
                child: Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    '$_total ${_total == 1 ? 'key' : 'keys'}',
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                ),
              ),
              Expanded(
                child: ListView.builder(
                  physics: const AlwaysScrollableScrollPhysics(),
                  padding: const EdgeInsets.fromLTRB(16, 4, 16, 96),
                  itemCount: _keys.length,
                  itemBuilder: (context, index) => _KeyCard(
                    summary: _keys[index],
                    onTap: () => _openDetail(_keys[index]),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _KeyCard extends StatelessWidget {
  const _KeyCard({required this.summary, required this.onTap});

  final KeySummary summary;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final muted = theme.textTheme.bodySmall?.copyWith(color: scheme.onSurfaceVariant);
    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              CircleAvatar(
                backgroundColor: scheme.primaryContainer,
                child: Icon(Icons.vpn_key_outlined,
                    size: 20, color: scheme.onPrimaryContainer),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            summary.name,
                            style: theme.textTheme.titleMedium,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        const SizedBox(width: 8),
                        StatusChip(summary.status, dense: true),
                      ],
                    ),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 12,
                      runSpacing: 4,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        Text(summary.algorithm, style: muted),
                        Text(
                          shortHex(summary.fingerprintSha256),
                          style: monoStyle.copyWith(
                              fontSize: 12, color: scheme.onSurfaceVariant),
                        ),
                        if (summary.certNotAfter != null)
                          Text(
                            'cert expires ${formatDate(summary.certNotAfter)}',
                            style: muted,
                          ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Icon(Icons.chevron_right, color: scheme.onSurfaceVariant),
            ],
          ),
        ),
      ),
    );
  }
}

class _GenerateKeyDialog extends StatefulWidget {
  const _GenerateKeyDialog({required this.client});

  final ApiClient client;

  @override
  State<_GenerateKeyDialog> createState() => _GenerateKeyDialogState();
}

class _GenerateKeyDialogState extends State<_GenerateKeyDialog> {
  final TextEditingController _name = TextEditingController();
  String _algorithm = kAlgorithms.first;
  bool _submitting = false;
  String? _error;

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final name = _name.text.trim();
    if (name.isEmpty) {
      setState(() => _error = 'INVALID_REQUEST — name is required');
      return;
    }
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final detail =
          await widget.client.createKey(name: name, algorithm: _algorithm);
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
      title: const Text('Generate key'),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _name,
              autofocus: true,
              decoration: const InputDecoration(
                labelText: 'Name',
                hintText: 'e.g. api-gateway-tls',
              ),
              onSubmitted: (_) => _submitting ? null : _submit(),
            ),
            const SizedBox(height: 16),
            DropdownButtonFormField<String>(
              initialValue: _algorithm,
              decoration: const InputDecoration(labelText: 'Algorithm'),
              items: [
                for (final algorithm in kAlgorithms)
                  DropdownMenuItem(value: algorithm, child: Text(algorithm)),
              ],
              onChanged: (value) =>
                  setState(() => _algorithm = value ?? _algorithm),
            ),
            if (_error != null) ...[
              const SizedBox(height: 14),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: scheme.errorContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  _error!,
                  style: TextStyle(color: scheme.onErrorContainer, fontSize: 13),
                ),
              ),
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
              : const Text('Generate'),
        ),
      ],
    );
  }
}
