import 'package:flutter_test/flutter_test.dart';

import 'package:cert_manager_ui/main.dart';

void main() {
  testWidgets('app boots to the connect screen', (WidgetTester tester) async {
    await tester.pumpWidget(const CertManagerApp());

    // AppBar title and headline both say "Certificate Manager".
    expect(find.text('Certificate Manager'), findsWidgets);
    // The credential form and its submit button are present.
    expect(find.text('Client ID'), findsOneWidget);
    expect(find.text('Client secret'), findsOneWidget);
    expect(find.text('Connect'), findsOneWidget);
  });
}
