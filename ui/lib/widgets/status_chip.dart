import 'package:flutter/material.dart';

/// Accent color for a key status, adjusted for the active brightness.
Color statusColor(String status, [Brightness brightness = Brightness.light]) {
  final dark = brightness == Brightness.dark;
  switch (status) {
    case 'CREATED':
      return dark ? Colors.blueGrey.shade300 : Colors.blueGrey.shade700;
    case 'READY_TO_PUBLISH':
      return dark ? Colors.amber.shade300 : Colors.amber.shade900;
    case 'ACTIVE':
      return dark ? Colors.green.shade300 : Colors.green.shade700;
    case 'COMPROMISED':
      return dark ? Colors.red.shade300 : Colors.red.shade700;
    case 'DELETED':
      return dark ? Colors.grey.shade400 : Colors.grey.shade600;
    default:
      return dark ? Colors.grey.shade400 : Colors.grey.shade600;
  }
}

/// Color-coded pill for a key lifecycle status.
class StatusChip extends StatelessWidget {
  const StatusChip(this.status, {super.key, this.dense = false});

  final String status;
  final bool dense;

  @override
  Widget build(BuildContext context) {
    final color = statusColor(status, Theme.of(context).brightness);
    return Container(
      padding: EdgeInsets.symmetric(horizontal: dense ? 8 : 10, vertical: dense ? 3 : 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.45)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(
            status,
            style: TextStyle(
              color: color,
              fontSize: dense ? 11 : 12,
              fontWeight: FontWeight.w600,
              letterSpacing: 0.3,
            ),
          ),
        ],
      ),
    );
  }
}
