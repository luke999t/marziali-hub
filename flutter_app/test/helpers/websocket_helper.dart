/// ================================================================================
/// 🎓 AI_MODULE: WebSocketHelper
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Helper per test WebSocket REALI - ZERO MOCK
/// 🎓 AI_BUSINESS: Utility per connessione e test WebSocket glasses.
///                 Tutte le connessioni vanno a backend REALE.
///                 Supporta test concurrency e stress.
/// 🎓 AI_TEACHING: WebSocket test patterns, connection lifecycle,
///                 message assertion, timeout handling.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 FEATURES:
/// - Connessione WebSocket con retry
/// - Send/receive con timeout
/// - Assert su messaggi ricevuti
/// - Multi-connection per stress test
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Connessione a ws://localhost:8000 REALE
/// - Nessun mock WebSocket
/// ================================================================================

import 'dart:async';
import 'dart:convert';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:web_socket_channel/status.dart' as ws_status;
import 'package:test/test.dart';
import 'test_config.dart';

/// Helper per test WebSocket
class WebSocketTestHelper {
  WebSocketChannel? _channel;
  StreamSubscription? _subscription;
  final List<Map<String, dynamic>> _receivedMessages = [];
  final _messageController = StreamController<Map<String, dynamic>>.broadcast();

  /// Stream di messaggi ricevuti
  Stream<Map<String, dynamic>> get messages => _messageController.stream;

  /// Lista messaggi ricevuti (per assertion)
  List<Map<String, dynamic>> get receivedMessages =>
      List.unmodifiable(_receivedMessages);

  /// True se connesso
  bool get isConnected => _channel != null;

  /// Ultimo messaggio ricevuto
  Map<String, dynamic>? get lastMessage =>
      _receivedMessages.isNotEmpty ? _receivedMessages.last : null;

  /// Connette a WebSocket glasses
  Future<void> connect({
    required String userId,
    String deviceType = 'test',
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final wsUrl = apiBaseUrl
        .replaceFirst('http://', 'ws://')
        .replaceFirst('https://', 'wss://');

    final uri = Uri.parse(
      '$wsUrl/api/v1/ws/glasses/$userId?device_type=$deviceType',
    );

    _channel = WebSocketChannel.connect(uri);
    await _channel!.ready.timeout(timeout);

    _subscription = _channel!.stream.listen(
      (data) {
        try {
          final message = jsonDecode(data as String) as Map<String, dynamic>;
          _receivedMessages.add(message);
          _messageController.add(message);
        } catch (e) {
          print('WebSocketHelper: Parse error: $e');
        }
      },
      onError: (e) {
        print('WebSocketHelper: Error: $e');
      },
      onDone: () {
        print('WebSocketHelper: Connection closed');
      },
    );
  }

  /// Disconnette
  Future<void> disconnect() async {
    await _subscription?.cancel();
    _subscription = null;

    try {
      await _channel?.sink.close(ws_status.normalClosure);
    } catch (e) {
      // Ignora errori chiusura
    }
    _channel = null;
  }

  /// Invia messaggio JSON
  void send(Map<String, dynamic> message) {
    if (_channel == null) {
      throw Exception('Not connected');
    }
    _channel!.sink.add(jsonEncode(message));
  }

  /// Invia comando
  void sendCommand(String command, dynamic value) {
    send({
      'type': 'command',
      'command': command,
      'value': value,
    });
  }

  /// Invia ping
  void sendPing() {
    send({'type': 'ping'});
  }

  /// Attende messaggio con tipo specifico
  Future<Map<String, dynamic>> waitForMessage(
    String type, {
    Duration timeout = const Duration(seconds: 5),
  }) async {
    // Check messaggi già ricevuti
    for (final msg in _receivedMessages) {
      if (msg['type'] == type) {
        return msg;
      }
    }

    // Aspetta nuovo messaggio
    return messages
        .where((msg) => msg['type'] == type)
        .first
        .timeout(timeout);
  }

  /// Attende state_sync iniziale
  Future<Map<String, dynamic>> waitForStateSync({
    Duration timeout = const Duration(seconds: 5),
  }) async {
    return waitForMessage('state_sync', timeout: timeout);
  }

  /// Attende state_update dopo comando
  Future<Map<String, dynamic>> waitForStateUpdate({
    Duration timeout = const Duration(seconds: 5),
  }) async {
    return waitForMessage('state_update', timeout: timeout);
  }

  /// Attende pong dopo ping
  Future<Map<String, dynamic>> waitForPong({
    Duration timeout = const Duration(seconds: 5),
  }) async {
    return waitForMessage('pong', timeout: timeout);
  }

  /// Pulisce messaggi ricevuti
  void clearMessages() {
    _receivedMessages.clear();
  }

  /// Conta messaggi di un tipo
  int countMessages(String type) {
    return _receivedMessages.where((m) => m['type'] == type).length;
  }

  /// Verifica che sia stato ricevuto un messaggio con tipo
  void assertReceivedMessage(String type) {
    expect(
      _receivedMessages.any((m) => m['type'] == type),
      isTrue,
      reason: 'Expected to receive message of type "$type"',
    );
  }

  /// Verifica che NON sia stato ricevuto un messaggio con tipo
  void assertNotReceivedMessage(String type) {
    expect(
      _receivedMessages.any((m) => m['type'] == type),
      isFalse,
      reason: 'Did not expect to receive message of type "$type"',
    );
  }

  /// Dispose
  Future<void> dispose() async {
    await disconnect();
    await _messageController.close();
    _receivedMessages.clear();
  }
}

/// Factory per creare multiple connessioni (stress test)
class WebSocketConnectionPool {
  final List<WebSocketTestHelper> _connections = [];

  /// Numero connessioni attive
  int get activeConnections => _connections.length;

  /// Crea N connessioni
  Future<void> createConnections({
    required int count,
    required String baseUserId,
    Duration delayBetween = const Duration(milliseconds: 100),
  }) async {
    for (int i = 0; i < count; i++) {
      final helper = WebSocketTestHelper();
      await helper.connect(userId: '${baseUserId}_$i');
      _connections.add(helper);

      if (delayBetween.inMilliseconds > 0 && i < count - 1) {
        await Future.delayed(delayBetween);
      }
    }
  }

  /// Invia comando a tutte le connessioni
  void broadcastCommand(String command, dynamic value) {
    for (final conn in _connections) {
      conn.sendCommand(command, value);
    }
  }

  /// Disconnette tutte
  Future<void> disconnectAll() async {
    for (final conn in _connections) {
      await conn.dispose();
    }
    _connections.clear();
  }

  /// Ottiene connessione specifica
  WebSocketTestHelper operator [](int index) => _connections[index];
}

/// Matcher per messaggi WebSocket
Matcher isWebSocketMessage(String type) => _WebSocketMessageMatcher(type);

class _WebSocketMessageMatcher extends Matcher {
  final String expectedType;

  _WebSocketMessageMatcher(this.expectedType);

  @override
  bool matches(dynamic item, Map matchState) {
    if (item is! Map<String, dynamic>) return false;
    return item['type'] == expectedType;
  }

  @override
  Description describe(Description description) {
    return description.add('WebSocket message of type "$expectedType"');
  }
}

/// Matcher per state con valore specifico
Matcher hasStateValue(String key, dynamic value) =>
    _StateValueMatcher(key, value);

class _StateValueMatcher extends Matcher {
  final String key;
  final dynamic expectedValue;

  _StateValueMatcher(this.key, this.expectedValue);

  @override
  bool matches(dynamic item, Map matchState) {
    if (item is! Map<String, dynamic>) return false;
    final state = item['state'];
    if (state is! Map<String, dynamic>) return false;
    return state[key] == expectedValue;
  }

  @override
  Description describe(Description description) {
    return description.add('state with $key = $expectedValue');
  }
}
