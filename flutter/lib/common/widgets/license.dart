import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/models/platform_model.dart';

/// License banner for builds with licensing enabled (src/license.rs). It stays
/// hidden when licensing is off, warns a week before expiry, and asks for a
/// code while the license is missing or expired.
class LicenseBanner extends StatefulWidget {
  const LicenseBanner({Key? key}) : super(key: key);

  @override
  State<LicenseBanner> createState() => _LicenseBannerState();
}

class _LicenseBannerState extends State<LicenseBanner> {
  Map<String, dynamic> _status = const {};
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) => _refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  void _refresh() {
    try {
      final s = jsonDecode(bind.mainGetCommonSync(key: 'license-status'));
      if (mounted && s is Map<String, dynamic>) {
        setState(() => _status = s);
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    if (_status['required'] != true) return const SizedBox.shrink();
    final valid = _status['valid'] == true;
    final expires = (_status['expires'] as num?)?.toInt() ?? 0;
    final daysLeft = expires > 0
        ? DateTime.fromMillisecondsSinceEpoch(expires * 1000)
            .difference(DateTime.now())
            .inDays
        : 9999;
    if (valid && daysLeft > 7) return const SizedBox.shrink();

    final String title;
    final String text;
    final Color color;
    if (valid) {
      title = 'Licența expiră în curând';
      text = 'Licența expiră pe ${_date(expires)}. Contactează RDN Network Data '
          'pentru prelungire.';
      color = Colors.orange.shade800;
    } else {
      title = 'Licență necesară';
      text = 'Aplicația funcționează doar cu un cod de licență valid. '
          'Introdu codul primit de la RDN Network Data.';
      color = Colors.red.shade700;
    }
    return Container(
      margin: const EdgeInsets.fromLTRB(12, 12, 12, 0),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        border: Border.all(color: color.withOpacity(0.5)),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Icon(valid ? Icons.schedule : Icons.lock_outline, color: color),
            const SizedBox(width: 8),
            Expanded(
                child: Text(title,
                    style:
                        TextStyle(fontWeight: FontWeight.w700, color: color))),
          ]),
          const SizedBox(height: 6),
          Text(text),
          const SizedBox(height: 10),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: color),
            onPressed: () async {
              await showLicenseDialog(context);
              _refresh();
            },
            child: Text(valid ? 'Introdu un cod nou' : 'Activează licența',
                style: const TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }
}

String _date(int unixSeconds) {
  final d = DateTime.fromMillisecondsSinceEpoch(unixSeconds * 1000);
  String two(int v) => v.toString().padLeft(2, '0');
  return '${two(d.day)}.${two(d.month)}.${d.year}';
}

Future<void> showLicenseDialog(BuildContext context) async {
  final controller = TextEditingController();
  String? error;
  bool busy = false;
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => StatefulBuilder(builder: (ctx, setState) {
      Future<void> submit() async {
        final code = controller.text.trim();
        if (code.isEmpty || busy) return;
        setState(() {
          busy = true;
          error = null;
        });
        String reply;
        try {
          reply = await bind.mainGetCommon(key: 'license-activate:$code');
        } catch (e) {
          reply = jsonEncode({'error': e.toString()});
        }
        Map<String, dynamic> r = {};
        try {
          r = jsonDecode(reply);
        } catch (_) {}
        if (r['ok'] == true) {
          if (ctx.mounted) Navigator.of(ctx).pop();
          return;
        }
        setState(() {
          busy = false;
          error = (r['error'] ?? 'Activarea a eșuat').toString();
        });
      }

      return AlertDialog(
        title: const Text('Activează licența'),
        content: SizedBox(
          width: 380,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Introdu codul de licență primit de la RDN Network Data.'),
              const SizedBox(height: 12),
              TextField(
                controller: controller,
                autofocus: true,
                textCapitalization: TextCapitalization.characters,
                decoration: const InputDecoration(
                  hintText: 'RDN-XXXX-XXXX-XXXX',
                  border: OutlineInputBorder(),
                ),
                onSubmitted: (_) => submit(),
              ),
              if (error != null) ...[
                const SizedBox(height: 10),
                Text(error!, style: TextStyle(color: Colors.red.shade700)),
              ],
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: busy ? null : () => Navigator.of(ctx).pop(),
            child: const Text('Renunță'),
          ),
          ElevatedButton(
            onPressed: busy ? null : submit,
            child: busy
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Activează'),
          ),
        ],
      );
    }),
  );
  controller.dispose();
}
