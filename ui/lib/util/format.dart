import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api/client.dart';

/// Monospace style used for PEM material, fingerprints and JSON detail.
const TextStyle monoStyle = TextStyle(
  fontFamily: 'monospace',
  fontFamilyFallback: <String>['Menlo', 'Consolas', 'Courier'],
  fontSize: 12.5,
  height: 1.45,
);

String _two(int n) => n.toString().padLeft(2, '0');

/// `2026-06-12 08:30:00 UTC` or an em-dash for null.
String formatTimestamp(DateTime? t) {
  if (t == null) return '—';
  final u = t.toUtc();
  return '${u.year}-${_two(u.month)}-${_two(u.day)} '
      '${_two(u.hour)}:${_two(u.minute)}:${_two(u.second)} UTC';
}

/// `2026-06-12` or an em-dash for null.
String formatDate(DateTime? t) {
  if (t == null) return '—';
  final u = t.toUtc();
  return '${u.year}-${_two(u.month)}-${_two(u.day)}';
}

/// First [length] characters of a hex digest with an ellipsis.
String shortHex(String hex, {int length = 16}) =>
    hex.length <= length ? hex : '${hex.substring(0, length)}…';

String describeError(Object error) =>
    error is ApiException ? error.display : 'UNEXPECTED — $error';

void showSnack(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message), behavior: SnackBarBehavior.floating));
}

/// Shows every API failure in the mandated "CODE — message" form.
void showErrorSnack(BuildContext context, Object error) =>
    showSnack(context, describeError(error));

Future<void> copyToClipboard(BuildContext context, String text) async {
  await Clipboard.setData(ClipboardData(text: text));
  if (context.mounted) showSnack(context, 'Copied to clipboard');
}
