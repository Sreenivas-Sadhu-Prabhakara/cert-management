import 'package:flutter/material.dart';

import 'api/client.dart';
import 'screens/connect_screen.dart';

void main() {
  runApp(const CertManagerApp());
}

/// Root widget: owns the [ApiClient] and routes any 401 back to the
/// connect screen.
class CertManagerApp extends StatefulWidget {
  const CertManagerApp({super.key});

  @override
  State<CertManagerApp> createState() => _CertManagerAppState();
}

class _CertManagerAppState extends State<CertManagerApp> {
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();
  late final ApiClient _client = ApiClient(onUnauthorized: _handleUnauthorized);

  /// Fired by [ApiClient] whenever an authenticated request comes back 401
  /// (expired/invalid token): drop everything and return to the connect screen.
  void _handleUnauthorized() {
    _navigatorKey.currentState?.pushAndRemoveUntil(
      MaterialPageRoute<void>(
        builder: (_) => ConnectScreen(
          client: _client,
          notice: 'Session expired or unauthorized — please connect again.',
        ),
      ),
      (route) => false,
    );
  }

  ThemeData _theme(Brightness brightness) => ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1565C0),
          brightness: brightness,
        ),
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
        ),
      );

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Certificate Manager',
      debugShowCheckedModeBanner: false,
      navigatorKey: _navigatorKey,
      theme: _theme(Brightness.light),
      darkTheme: _theme(Brightness.dark),
      themeMode: ThemeMode.system,
      home: ConnectScreen(client: _client),
    );
  }
}
