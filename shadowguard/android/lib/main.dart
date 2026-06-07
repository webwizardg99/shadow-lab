// ShadowGuard Android App
// Minimal UI — web dashboard a localhost:8888-on, natív WiFi scan + alert
//
// Fordítás: flutter build apk --release
// Függőségek: pubspec.yaml-ban (wifi_scan, permission_handler, flutter_local_notifications)

import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:wifi_scan/wifi_scan.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await _initNotifications();
  runApp(const ShadowGuardApp());
}

// ── Notification setup ─────────────────────────────────────────────────────

final FlutterLocalNotificationsPlugin _notif = FlutterLocalNotificationsPlugin();

Future<void> _initNotifications() async {
  const android = AndroidInitializationSettings('@mipmap/ic_launcher');
  await _notif.initialize(const InitializationSettings(android: android));
}

Future<void> _showThreatNotif(String title, String body, String severity) async {
  final color = severity == 'critical'
      ? const Color(0xFFFF3333)
      : severity == 'high'
          ? const Color(0xFFFF8800)
          : const Color(0xFFFFCC00);

  await _notif.show(
    DateTime.now().millisecondsSinceEpoch ~/ 1000,
    title,
    body,
    NotificationDetails(
      android: AndroidNotificationDetails(
        'shadowguard_threats', 'ShadowGuard Threats',
        importance: Importance.max,
        priority: Priority.high,
        color: color,
        enableVibration: true,
        playSound: true,
      ),
    ),
  );
}

// ── App ────────────────────────────────────────────────────────────────────

class ShadowGuardApp extends StatelessWidget {
  const ShadowGuardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ShadowGuard',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.dark(
          primary: const Color(0xFF00E5FF),
          surface: const Color(0xFF0D1117),
        ),
        scaffoldBackgroundColor: const Color(0xFF0D1117),
        cardColor: const Color(0xFF161B22),
        useMaterial3: true,
      ),
      home: const ShadowGuardHome(),
    );
  }
}

// ── Home screen ────────────────────────────────────────────────────────────

class ShadowGuardHome extends StatefulWidget {
  const ShadowGuardHome({super.key});

  @override
  State<ShadowGuardHome> createState() => _ShadowGuardHomeState();
}

class _ShadowGuardHomeState extends State<ShadowGuardHome> {
  final WifiDetector _detector = WifiDetector();
  List<ThreatEvent> _threats   = [];
  List<WifiNetwork> _networks  = [];
  bool  _monitoring  = false;
  bool  _scanning    = false;
  String _status     = 'Idle';
  Timer? _scanTimer;

  @override
  void initState() {
    super.initState();
    _requestPermissions();
    _detector.onThreat = _onThreat;
  }

  Future<void> _requestPermissions() async {
    await [
      Permission.location,
      Permission.locationWhenInUse,
      Permission.nearbyWifiDevices,
    ].request();
  }

  void _onThreat(ThreatEvent t) {
    setState(() => _threats.insert(0, t));
    _showThreatNotif(
      '${t.type} — ${t.ssid}',
      t.message,
      t.severity,
    );
  }

  Future<void> _scan() async {
    setState(() { _scanning = true; _status = 'Scanning...'; });
    final nets = await _detector.scan();
    setState(() {
      _networks = nets;
      _scanning = false;
      _status   = 'Scan complete — ${nets.length} networks';
    });
  }

  void _toggleMonitor() {
    if (_monitoring) {
      _scanTimer?.cancel();
      setState(() { _monitoring = false; _status = 'Monitoring stopped'; });
    } else {
      _scan();
      _scanTimer = Timer.periodic(const Duration(seconds: 10), (_) => _scan());
      setState(() { _monitoring = true; _status = 'Monitoring active'; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF0D1117),
        title: Row(children: [
          Container(
            width: 10, height: 10,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: _monitoring ? const Color(0xFF00FF88) : Colors.grey,
            ),
          ),
          const SizedBox(width: 8),
          const Text('ShadowGuard',
              style: TextStyle(color: Color(0xFF00E5FF),
                               fontWeight: FontWeight.bold)),
        ]),
        actions: [
          if (_threats.isNotEmpty)
            Badge(
              label: Text('${_threats.length}'),
              child: IconButton(
                icon: const Icon(Icons.warning_amber),
                color: const Color(0xFFFF3333),
                onPressed: () => _showThreatsSheet(),
              ),
            ),
        ],
      ),
      body: Column(children: [
        // Status bar
        Container(
          width: double.infinity,
          color: const Color(0xFF161B22),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Text(
            _status,
            style: TextStyle(
              color: _monitoring ? const Color(0xFF00E5FF) : Colors.grey,
              fontSize: 13,
            ),
          ),
        ),

        // Network list
        Expanded(
          child: _scanning
              ? const Center(child: CircularProgressIndicator(
                  color: Color(0xFF00E5FF)))
              : _networks.isEmpty
                  ? const Center(
                      child: Text('Tap scan to see nearby networks',
                          style: TextStyle(color: Colors.grey)))
                  : ListView.builder(
                      itemCount: _networks.length,
                      itemBuilder: (_, i) => _NetworkTile(
                        network: _networks[i],
                        onTrust: () => _trustNetwork(_networks[i]),
                      ),
                    ),
        ),

        // Recent threats
        if (_threats.isNotEmpty)
          Container(
            height: 90,
            color: const Color(0xFF1A0000),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Padding(
                  padding: EdgeInsets.only(left: 16, top: 8),
                  child: Text('ACTIVE THREATS',
                      style: TextStyle(color: Color(0xFFFF3333),
                                       fontSize: 11,
                                       fontWeight: FontWeight.bold,
                                       letterSpacing: 1.5)),
                ),
                Expanded(
                  child: ListView.builder(
                    scrollDirection: Axis.horizontal,
                    itemCount: _threats.length,
                    itemBuilder: (_, i) => _ThreatChip(threat: _threats[i]),
                  ),
                ),
              ],
            ),
          ),
      ]),

      // FAB
      floatingActionButton: Column(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          FloatingActionButton.small(
            heroTag: 'scan',
            backgroundColor: const Color(0xFF161B22),
            onPressed: _scan,
            child: const Icon(Icons.wifi_find, color: Color(0xFF00E5FF)),
          ),
          const SizedBox(height: 8),
          FloatingActionButton.extended(
            heroTag: 'monitor',
            backgroundColor: _monitoring
                ? const Color(0xFF1A3A1A)
                : const Color(0xFF003344),
            onPressed: _toggleMonitor,
            icon: Icon(
              _monitoring ? Icons.shield : Icons.shield_outlined,
              color: _monitoring ? const Color(0xFF00FF88) : const Color(0xFF00E5FF),
            ),
            label: Text(
              _monitoring ? 'Protected' : 'Start Guard',
              style: TextStyle(
                color: _monitoring ? const Color(0xFF00FF88) : const Color(0xFF00E5FF),
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _trustNetwork(WifiNetwork net) async {
    await _detector.trust(net);
    setState(() {
      _status = 'Trusted: ${net.ssid}';
    });
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('${net.ssid} added to trusted networks'),
          backgroundColor: const Color(0xFF003322),
        ),
      );
    }
  }

  void _showThreatsSheet() {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF161B22),
      builder: (_) => ListView.builder(
        itemCount: _threats.length,
        itemBuilder: (_, i) {
          final t = _threats[i];
          return ListTile(
            leading: Icon(
              Icons.warning,
              color: t.severity == 'critical' ? Colors.red : Colors.orange,
            ),
            title: Text(t.type,
                style: const TextStyle(color: Colors.white,
                                       fontWeight: FontWeight.bold)),
            subtitle: Text(t.message,
                style: const TextStyle(color: Colors.grey, fontSize: 12)),
          );
        },
      ),
    );
  }

  @override
  void dispose() {
    _scanTimer?.cancel();
    super.dispose();
  }
}

// ── Network tile ──────────────────────────────────────────────────────────

class _NetworkTile extends StatelessWidget {
  final WifiNetwork network;
  final VoidCallback onTrust;
  const _NetworkTile({required this.network, required this.onTrust});

  @override
  Widget build(BuildContext context) {
    final secColor = network.isThreat
        ? Colors.red
        : network.isTrusted
            ? const Color(0xFF00FF88)
            : Colors.grey;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      color: network.isThreat
          ? const Color(0xFF2A0000)
          : network.isTrusted
              ? const Color(0xFF002A00)
              : const Color(0xFF161B22),
      child: ListTile(
        dense: true,
        leading: Icon(
          network.isThreat ? Icons.warning : Icons.wifi,
          color: secColor,
        ),
        title: Text(
          network.ssid,
          style: TextStyle(
            color: network.isThreat ? Colors.red : Colors.white,
            fontWeight: FontWeight.w500,
          ),
        ),
        subtitle: Text(
          '${network.bssid}  •  ${network.security}  •  ${network.rssi} dBm',
          style: const TextStyle(color: Colors.grey, fontSize: 11),
        ),
        trailing: network.isTrusted
            ? const Icon(Icons.verified, color: Color(0xFF00FF88), size: 18)
            : IconButton(
                icon: const Icon(Icons.add_circle_outline,
                                 color: Color(0xFF00E5FF), size: 18),
                onPressed: onTrust,
                tooltip: 'Trust this network',
              ),
      ),
    );
  }
}

class _ThreatChip extends StatelessWidget {
  final ThreatEvent threat;
  const _ThreatChip({required this.threat});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 6, vertical: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: const Color(0xFF2A0000),
        border: Border.all(color: Colors.red.withOpacity(0.6)),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(threat.type,
              style: const TextStyle(color: Colors.red,
                                     fontWeight: FontWeight.bold,
                                     fontSize: 11)),
          Text(threat.ssid,
              style: const TextStyle(color: Colors.white70, fontSize: 11)),
        ],
      ),
    );
  }
}

// ── Detector (wraps platform WiFi scan + detection logic) ─────────────────

class WifiNetwork {
  final String ssid, bssid, security;
  final int rssi, channel;
  bool isTrusted;
  bool isThreat;

  WifiNetwork({
    required this.ssid, required this.bssid,
    required this.security, required this.rssi, required this.channel,
    this.isTrusted = false, this.isThreat = false,
  });
}

class ThreatEvent {
  final String type, severity, ssid, bssid, message;
  final DateTime time;
  ThreatEvent({required this.type, required this.severity,
               required this.ssid, required this.bssid,
               required this.message})
      : time = DateTime.now();
}

class WifiDetector {
  Function(ThreatEvent)? onThreat;

  // Trusted network fingerprints: ssid → Set<bssid>
  final Map<String, Set<String>> _trusted     = {};
  final Map<String, String>      _trustedSec  = {};   // bssid → security
  final Map<String, int>         _lastRssi    = {};   // bssid → rssi

  Future<List<WifiNetwork>> scan() async {
    final can = await WiFiScan.instance.canStartScan(askPermissions: true);
    if (can != CanStartScan.yes) return [];

    await WiFiScan.instance.startScan();
    await Future.delayed(const Duration(seconds: 2));

    final results = await WiFiScan.instance.getScannedResults();
    final networks = <WifiNetwork>[];
    final ssidGroups = <String, List<WiFiAccessPoint>>{};

    for (final ap in results) {
      final ssid = ap.ssid;
      if (ssid.isEmpty) continue;
      ssidGroups.putIfAbsent(ssid, () => []).add(ap);
    }

    for (final entry in ssidGroups.entries) {
      final ssid = entry.key;
      final aps  = entry.value;

      // Evil Twin check: known SSID with unknown BSSID
      final knownBssids = _trusted[ssid];

      for (final ap in aps) {
        final bssid    = ap.bssid;
        final security = _parseSecurity(ap.capabilities);
        final rssi     = ap.level;
        bool isThreat  = false;

        if (knownBssids != null && knownBssids.isNotEmpty) {
          // Evil twin
          if (!knownBssids.contains(bssid)) {
            isThreat = true;
            onThreat?.call(ThreatEvent(
              type: 'EVIL_TWIN', severity: 'critical',
              ssid: ssid, bssid: bssid,
              message: 'Unknown BSSID for trusted network "$ssid" — possible Evil Twin',
            ));
          }
          // Security downgrade
          final knownSec = _trustedSec[knownBssids.first];
          if (knownSec != null &&
              (knownSec == 'WPA2' || knownSec == 'WPA3') &&
              (security == 'Open' || security == 'WEP')) {
            isThreat = true;
            onThreat?.call(ThreatEvent(
              type: 'DOWNGRADE', severity: 'critical',
              ssid: ssid, bssid: bssid,
              message: 'Security downgrade on "$ssid": $knownSec → $security',
            ));
          }
        }

        // Signal spike
        final prevRssi = _lastRssi[bssid];
        if (prevRssi != null && rssi - prevRssi > 15) {
          onThreat?.call(ThreatEvent(
            type: 'SIGNAL_SPIKE', severity: 'high',
            ssid: ssid, bssid: bssid,
            message: 'Sudden signal spike on "$ssid": $prevRssi → $rssi dBm',
          ));
        }
        _lastRssi[bssid] = rssi;

        networks.add(WifiNetwork(
          ssid: ssid, bssid: bssid, security: security,
          rssi: rssi, channel: ap.frequency ~/ 5 - 1000,
          isTrusted: knownBssids?.contains(bssid) ?? false,
          isThreat: isThreat,
        ));
      }

      // KARMA: 3+ APs with same SSID
      if (aps.length >= 3) {
        onThreat?.call(ThreatEvent(
          type: 'KARMA', severity: 'high',
          ssid: ssid, bssid: aps.first.bssid,
          message: '${aps.length} APs broadcasting "$ssid" — possible KARMA attack',
        ));
      }
    }

    return networks..sort((a, b) => b.rssi.compareTo(a.rssi));
  }

  Future<void> trust(WifiNetwork net) async {
    _trusted.putIfAbsent(net.ssid, () => {}).add(net.bssid);
    _trustedSec[net.bssid] = net.security;
    // TODO: persist to SharedPreferences
  }

  String _parseSecurity(String caps) {
    if (caps.contains('WPA3')) return 'WPA3';
    if (caps.contains('WPA2')) return 'WPA2';
    if (caps.contains('WPA'))  return 'WPA';
    if (caps.contains('WEP'))  return 'WEP';
    return 'Open';
  }
}
