import 'package:flutter/material.dart';

import '../api/client.dart';
import '../util/format.dart';
import 'docs_screen.dart';
import 'keys_list_screen.dart';

/// A selectable backend target.
class BackendOption {
  const BackendOption(this.label, this.baseUrl);

  final String label;
  final String baseUrl;

  bool get isCustom => baseUrl.isEmpty;

  /// Short tag shown in the AppBar after connecting.
  String get shortLabel => isCustom ? 'Custom' : label.split(' ').first;
}

const List<BackendOption> kBackendOptions = [
  BackendOption('Java — localhost:8081', 'http://localhost:8081'),
  BackendOption('Go — localhost:8082', 'http://localhost:8082'),
  BackendOption('Node — localhost:8083', 'http://localhost:8083'),
  BackendOption('Rust — localhost:8084', 'http://localhost:8084'),
  BackendOption('Custom base URL', ''),
];

/// Entry screen: pick a backend, supply client credentials, fetch a token.
class ConnectScreen extends StatefulWidget {
  const ConnectScreen({super.key, required this.client, this.notice});

  final ApiClient client;

  /// Optional banner text, e.g. after a session expiry.
  final String? notice;

  @override
  State<ConnectScreen> createState() => _ConnectScreenState();
}

class _ConnectScreenState extends State<ConnectScreen> {
  BackendOption _backend = kBackendOptions.first;
  final TextEditingController _customUrl =
      TextEditingController(text: 'http://localhost:8081');
  final TextEditingController _clientId = TextEditingController(text: 'admin');
  final TextEditingController _clientSecret = TextEditingController();
  bool _obscureSecret = true;
  bool _connecting = false;
  String? _error;

  @override
  void dispose() {
    _customUrl.dispose();
    _clientId.dispose();
    _clientSecret.dispose();
    super.dispose();
  }

  String get _baseUrl =>
      (_backend.isCustom ? _customUrl.text : _backend.baseUrl).trim();

  Future<void> _connect() async {
    final baseUrl = _baseUrl.replaceAll(RegExp(r'/+$'), '');
    final uri = Uri.tryParse(baseUrl);
    if (baseUrl.isEmpty || uri == null || !uri.hasScheme) {
      setState(() => _error =
          'INVALID_REQUEST — enter a valid base URL, e.g. http://localhost:8081');
      return;
    }
    if (_clientId.text.trim().isEmpty || _clientSecret.text.isEmpty) {
      setState(() =>
          _error = 'INVALID_REQUEST — client id and client secret are required');
      return;
    }
    setState(() {
      _connecting = true;
      _error = null;
    });
    try {
      await widget.client.connect(
        baseUrl: baseUrl,
        backendLabel: _backend.shortLabel,
        clientId: _clientId.text.trim(),
        clientSecret: _clientSecret.text,
      );
      if (!mounted) return;
      Navigator.of(context).pushReplacement(
        MaterialPageRoute<void>(
          builder: (_) => KeysListScreen(client: widget.client),
        ),
      );
    } catch (e) {
      if (mounted) setState(() => _error = describeError(e));
    } finally {
      if (mounted) setState(() => _connecting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Certificate Manager'),
        actions: [
          IconButton(
            tooltip: 'Documentation',
            icon: const Icon(Icons.menu_book_outlined),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute<void>(builder: (_) => const DocsScreen()),
            ),
          ),
        ],
      ),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                CircleAvatar(
                  radius: 28,
                  backgroundColor: scheme.primaryContainer,
                  child: Icon(Icons.shield_outlined,
                      size: 30, color: scheme.onPrimaryContainer),
                ),
                const SizedBox(height: 16),
                Text(
                  'Certificate Manager',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.headlineSmall,
                ),
                const SizedBox(height: 6),
                Text(
                  'Manage SSL/TLS key pairs, CSRs and certificate chains '
                  'across four interchangeable backends.',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodyMedium
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: 24),
                if (widget.notice != null) ...[
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: scheme.tertiaryContainer,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      children: [
                        Icon(Icons.info_outline,
                            size: 20, color: scheme.onTertiaryContainer),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            widget.notice!,
                            style: TextStyle(
                                color: scheme.onTertiaryContainer, fontSize: 13),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                ],
                Card(
                  margin: EdgeInsets.zero,
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        DropdownButtonFormField<BackendOption>(
                          initialValue: _backend,
                          isExpanded: true,
                          decoration: const InputDecoration(
                            labelText: 'Backend',
                            prefixIcon: Icon(Icons.dns_outlined),
                          ),
                          items: [
                            for (final option in kBackendOptions)
                              DropdownMenuItem(
                                value: option,
                                child: Text(
                                  option.label,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                          ],
                          onChanged: (value) =>
                              setState(() => _backend = value ?? _backend),
                        ),
                        if (_backend.isCustom) ...[
                          const SizedBox(height: 14),
                          TextField(
                            controller: _customUrl,
                            decoration: const InputDecoration(
                              labelText: 'Base URL',
                              hintText: 'http://host:port',
                              prefixIcon: Icon(Icons.link_outlined),
                            ),
                            keyboardType: TextInputType.url,
                          ),
                        ],
                        const SizedBox(height: 14),
                        TextField(
                          controller: _clientId,
                          decoration: const InputDecoration(
                            labelText: 'Client ID',
                            prefixIcon: Icon(Icons.person_outline),
                          ),
                        ),
                        const SizedBox(height: 14),
                        TextField(
                          controller: _clientSecret,
                          obscureText: _obscureSecret,
                          decoration: InputDecoration(
                            labelText: 'Client secret',
                            prefixIcon: const Icon(Icons.password_outlined),
                            suffixIcon: IconButton(
                              tooltip: _obscureSecret ? 'Show' : 'Hide',
                              icon: Icon(_obscureSecret
                                  ? Icons.visibility_outlined
                                  : Icons.visibility_off_outlined),
                              onPressed: () => setState(
                                  () => _obscureSecret = !_obscureSecret),
                            ),
                          ),
                          onSubmitted: (_) => _connecting ? null : _connect(),
                        ),
                        if (_error != null) ...[
                          const SizedBox(height: 14),
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: scheme.errorContainer,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              _error!,
                              style: TextStyle(
                                  color: scheme.onErrorContainer, fontSize: 13),
                            ),
                          ),
                        ],
                        const SizedBox(height: 20),
                        FilledButton(
                          onPressed: _connecting ? null : _connect,
                          style: FilledButton.styleFrom(
                            padding: const EdgeInsets.symmetric(vertical: 14),
                          ),
                          child: _connecting
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child:
                                      CircularProgressIndicator(strokeWidth: 2),
                                )
                              : const Text('Connect'),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  'The access token is held in memory only and expires '
                  'automatically. You will be returned here when it does.',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
