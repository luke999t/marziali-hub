/// ================================================================================
/// 🎓 AI_MODULE: GlassesFixtures
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Test fixtures per modulo Smart Glasses - ZERO MOCK
/// 🎓 AI_BUSINESS: Dati di test realistici per glasses, skeleton, player.
///                 Riutilizzabili in unit, integration, e2e tests.
///                 Allineati con backend per consistency.
/// 🎓 AI_TEACHING: Test fixture patterns, factory methods,
///                 realistic test data generation.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 FEATURES:
/// - GlassesState fixtures con stati tipici
/// - Skeleton frame fixtures con MediaPipe landmarks
/// - Subtitle fixtures multilingua
/// - WebSocket message fixtures
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Fixtures sono DATI, non mock
/// - Usati per input test, non per faking backend
/// - Backend deve essere attivo per usare questi dati
/// ================================================================================

import '../../lib/services/glasses_service.dart';

// =============================================================================
// GLASSES STATE FIXTURES
// =============================================================================

/// Stati GlassesState per test
class GlassesStateFixtures {
  /// Stato iniziale (default values)
  static const GlassesState initial = GlassesState();

  /// Stato con video in riproduzione
  static const GlassesState playing = GlassesState(
    isPlaying: true,
    videoId: 'video_test_001',
    currentTimeMs: 30000, // 30 secondi
    volume: 70,
    brightness: 80,
  );

  /// Stato in pausa con skeleton visibile
  static const GlassesState pausedWithSkeleton = GlassesState(
    isPlaying: false,
    videoId: 'video_test_002',
    currentTimeMs: 60000, // 1 minuto
    skeletonVisible: true,
  );

  /// Stato con zoom e velocità modificati
  static const GlassesState zoomedSlowMotion = GlassesState(
    isPlaying: true,
    videoId: 'video_test_003',
    zoomLevel: 2.5,
    playbackSpeed: 0.5,
    currentTimeMs: 120000, // 2 minuti
  );

  /// Stato con volume e luminosità bassi (visione notturna)
  static const GlassesState nightMode = GlassesState(
    isPlaying: true,
    videoId: 'video_test_004',
    brightness: 20,
    volume: 30,
  );

  /// Stato con più device connessi
  static GlassesState multiDevice({int devices = 3}) => GlassesState(
        isPlaying: true,
        videoId: 'video_test_005',
        connectedDevices: devices,
        lastUpdate: DateTime.now(),
      );

  /// Lista di tutti gli stati per property-based testing
  static List<GlassesState> get allFixtures => [
        initial,
        playing,
        pausedWithSkeleton,
        zoomedSlowMotion,
        nightMode,
        multiDevice(),
      ];
}

// =============================================================================
// WEBSOCKET MESSAGE FIXTURES
// =============================================================================

/// Messaggi WebSocket tipici per test
class WebSocketMessageFixtures {
  /// Ping request
  static const Map<String, dynamic> ping = {'type': 'ping'};

  /// Pong response
  static const Map<String, dynamic> pong = {'type': 'pong'};

  /// State request
  static const Map<String, dynamic> stateRequest = {'type': 'state_request'};

  /// State sync message (ricevuto dopo connect)
  static Map<String, dynamic> stateSync({
    GlassesState? state,
  }) =>
      {
        'type': 'state_sync',
        'state': {
          'zoom_level': (state ?? GlassesStateFixtures.initial).zoomLevel,
          'playback_speed':
              (state ?? GlassesStateFixtures.initial).playbackSpeed,
          'is_playing': (state ?? GlassesStateFixtures.initial).isPlaying,
          'current_time_ms':
              (state ?? GlassesStateFixtures.initial).currentTimeMs,
          'skeleton_visible':
              (state ?? GlassesStateFixtures.initial).skeletonVisible,
          'brightness': (state ?? GlassesStateFixtures.initial).brightness,
          'volume': (state ?? GlassesStateFixtures.initial).volume,
          'video_id': (state ?? GlassesStateFixtures.initial).videoId,
          'connected_devices':
              (state ?? GlassesStateFixtures.initial).connectedDevices,
          'last_update': DateTime.now().toIso8601String(),
        },
      };

  /// Command: set zoom
  static Map<String, dynamic> commandZoom(double level) => {
        'type': 'command',
        'command': 'zoom',
        'value': level,
      };

  /// Command: set speed
  static Map<String, dynamic> commandSpeed(double speed) => {
        'type': 'command',
        'command': 'speed',
        'value': speed,
      };

  /// Command: play
  static const Map<String, dynamic> commandPlay = {
    'type': 'command',
    'command': 'play',
    'value': null,
  };

  /// Command: pause
  static const Map<String, dynamic> commandPause = {
    'type': 'command',
    'command': 'pause',
    'value': null,
  };

  /// Command: toggle skeleton
  static const Map<String, dynamic> commandToggleSkeleton = {
    'type': 'command',
    'command': 'toggle_skeleton',
    'value': null,
  };

  /// Device joined event
  static Map<String, dynamic> deviceJoined({
    String deviceType = 'glasses',
    int totalDevices = 2,
  }) =>
      {
        'type': 'device_joined',
        'device_type': deviceType,
        'connected_devices': totalDevices,
      };

  /// Device left event
  static Map<String, dynamic> deviceLeft({
    String deviceType = 'glasses',
    int totalDevices = 1,
  }) =>
      {
        'type': 'device_left',
        'device_type': deviceType,
        'connected_devices': totalDevices,
      };

  /// Error message
  static Map<String, dynamic> error(String message) => {
        'type': 'error',
        'error': message,
      };
}

// =============================================================================
// SKELETON FRAME FIXTURES
// =============================================================================

/// Dati skeleton per test overlay
class SkeletonFixtures {
  /// Single landmark (nose)
  /// 🔧 FIX: API usa 'index' non 'id', 'name' è getter non campo
  static Map<String, dynamic> get noseLandmark => {
        'index': 0,
        'x': 0.5,
        'y': 0.3,
        'z': 0.0,
        'visibility': 0.95,
      };

  /// MediaPipe Pose 33 landmarks - standing position
  /// 🔧 FIX: API usa 'index' non 'id', 'name' è getter calcolato da index
  static List<Map<String, dynamic>> get standingPose => [
    // Face
    {'index': 0, 'x': 0.5, 'y': 0.15, 'z': 0.0, 'visibility': 0.99},
    {'index': 1, 'x': 0.48, 'y': 0.13, 'z': 0.0, 'visibility': 0.98},
    {'index': 2, 'x': 0.46, 'y': 0.13, 'z': 0.0, 'visibility': 0.98},
    {'index': 3, 'x': 0.44, 'y': 0.13, 'z': 0.0, 'visibility': 0.97},
    {'index': 4, 'x': 0.52, 'y': 0.13, 'z': 0.0, 'visibility': 0.98},
    {'index': 5, 'x': 0.54, 'y': 0.13, 'z': 0.0, 'visibility': 0.98},
    {'index': 6, 'x': 0.56, 'y': 0.13, 'z': 0.0, 'visibility': 0.97},
    {'index': 7, 'x': 0.42, 'y': 0.14, 'z': 0.0, 'visibility': 0.90},
    {'index': 8, 'x': 0.58, 'y': 0.14, 'z': 0.0, 'visibility': 0.90},
    {'index': 9, 'x': 0.47, 'y': 0.18, 'z': 0.0, 'visibility': 0.95},
    {'index': 10, 'x': 0.53, 'y': 0.18, 'z': 0.0, 'visibility': 0.95},
    // Shoulders
    {'index': 11, 'x': 0.35, 'y': 0.28, 'z': 0.0, 'visibility': 0.99},
    {'index': 12, 'x': 0.65, 'y': 0.28, 'z': 0.0, 'visibility': 0.99},
    // Arms
    {'index': 13, 'x': 0.28, 'y': 0.42, 'z': 0.0, 'visibility': 0.95},
    {'index': 14, 'x': 0.72, 'y': 0.42, 'z': 0.0, 'visibility': 0.95},
    {'index': 15, 'x': 0.25, 'y': 0.55, 'z': 0.0, 'visibility': 0.90},
    {'index': 16, 'x': 0.75, 'y': 0.55, 'z': 0.0, 'visibility': 0.90},
    // Hands
    {'index': 17, 'x': 0.23, 'y': 0.58, 'z': 0.0, 'visibility': 0.80},
    {'index': 18, 'x': 0.77, 'y': 0.58, 'z': 0.0, 'visibility': 0.80},
    {'index': 19, 'x': 0.24, 'y': 0.57, 'z': 0.0, 'visibility': 0.85},
    {'index': 20, 'x': 0.76, 'y': 0.57, 'z': 0.0, 'visibility': 0.85},
    {'index': 21, 'x': 0.26, 'y': 0.56, 'z': 0.0, 'visibility': 0.85},
    {'index': 22, 'x': 0.74, 'y': 0.56, 'z': 0.0, 'visibility': 0.85},
    // Hips
    {'index': 23, 'x': 0.42, 'y': 0.55, 'z': 0.0, 'visibility': 0.98},
    {'index': 24, 'x': 0.58, 'y': 0.55, 'z': 0.0, 'visibility': 0.98},
    // Legs
    {'index': 25, 'x': 0.42, 'y': 0.72, 'z': 0.0, 'visibility': 0.95},
    {'index': 26, 'x': 0.58, 'y': 0.72, 'z': 0.0, 'visibility': 0.95},
    {'index': 27, 'x': 0.42, 'y': 0.90, 'z': 0.0, 'visibility': 0.90},
    {'index': 28, 'x': 0.58, 'y': 0.90, 'z': 0.0, 'visibility': 0.90},
    // Feet
    {'index': 29, 'x': 0.41, 'y': 0.92, 'z': 0.0, 'visibility': 0.85},
    {'index': 30, 'x': 0.59, 'y': 0.92, 'z': 0.0, 'visibility': 0.85},
    {'index': 31, 'x': 0.40, 'y': 0.94, 'z': 0.0, 'visibility': 0.80},
    {'index': 32, 'x': 0.60, 'y': 0.94, 'z': 0.0, 'visibility': 0.80},
  ];

  /// Skeleton frame completo
  static Map<String, dynamic> get standingFrame => {
        'timestamp_ms': 1000,
        'landmarks': standingPose,
        'confidence': 0.95,
      };

  /// Due frame per test interpolazione
  static List<Map<String, dynamic>> get twoFramesForInterpolation => [
    standingFrame,
    {
      'timestamp_ms': 2000,
      'landmarks': standingPose.map((l) => {
        ...l,
        'y': (l['y'] as double) + 0.05, // Leggero movimento verso il basso
      }).toList(),
      'confidence': 0.93,
    },
  ];

  /// Frame con low confidence (per test filtering)
  static Map<String, dynamic> get lowConfidenceFrame => {
        'timestamp_ms': 3000,
        'landmarks': standingPose.map((l) => {
          ...l,
          'visibility': 0.3, // Bassa visibilità
        }).toList(),
        'confidence': 0.4,
      };
}

// =============================================================================
// SUBTITLE FIXTURES
// =============================================================================

/// Sottotitoli per test
class SubtitleFixtures {
  /// Sottotitolo italiano singolo
  static Map<String, dynamic> get italianCue => {
        'start_ms': 0,
        'end_ms': 5000,
        'text': 'Questa è la posizione base del Kung Fu.',
        'language': 'it',
      };

  /// Sottotitolo con termine tecnico
  static Map<String, dynamic> get technicalTermCue => {
        'start_ms': 5000,
        'end_ms': 10000,
        'text': 'Eseguiamo ora il [Mabu] (posizione del cavaliere).',
        'language': 'it',
        'terms': [
          {
            'term': 'Mabu',
            'definition': 'Posizione fondamentale con gambe divaricate',
            'start': 16,
            'end': 20,
          }
        ],
      };

  /// Lista sottotitoli italiano
  static List<Map<String, dynamic>> get italianSubtitles => [
    {'start_ms': 0, 'end_ms': 3000, 'text': 'Benvenuti alla lezione.'},
    {'start_ms': 3000, 'end_ms': 6000, 'text': 'Oggi impareremo il Mabu.'},
    {'start_ms': 6000, 'end_ms': 9000, 'text': 'Piedi alla larghezza delle spalle.'},
    {'start_ms': 9000, 'end_ms': 12000, 'text': 'Ginocchia piegate, schiena dritta.'},
    {'start_ms': 12000, 'end_ms': 15000, 'text': 'Mantenete la posizione.'},
  ];

  /// Lista sottotitoli inglese
  static List<Map<String, dynamic>> get englishSubtitles => [
    {'start_ms': 0, 'end_ms': 3000, 'text': 'Welcome to the lesson.'},
    {'start_ms': 3000, 'end_ms': 6000, 'text': 'Today we will learn Mabu.'},
    {'start_ms': 6000, 'end_ms': 9000, 'text': 'Feet shoulder width apart.'},
    {'start_ms': 9000, 'end_ms': 12000, 'text': 'Knees bent, back straight.'},
    {'start_ms': 12000, 'end_ms': 15000, 'text': 'Hold the position.'},
  ];

  /// Lista sottotitoli cinese
  static List<Map<String, dynamic>> get chineseSubtitles => [
    {'start_ms': 0, 'end_ms': 3000, 'text': '欢迎来到课程。'},
    {'start_ms': 3000, 'end_ms': 6000, 'text': '今天我们学习马步。'},
    {'start_ms': 6000, 'end_ms': 9000, 'text': '双脚与肩同宽。'},
    {'start_ms': 9000, 'end_ms': 12000, 'text': '膝盖弯曲，背部挺直。'},
    {'start_ms': 12000, 'end_ms': 15000, 'text': '保持这个姿势。'},
  ];

  /// Mappa completa multilingua
  static Map<String, List<Map<String, dynamic>>> get allLanguages => {
        'it': italianSubtitles,
        'en': englishSubtitles,
        'zh': chineseSubtitles,
      };
}

// =============================================================================
// VIDEO FIXTURES
// =============================================================================

/// Video metadata per test
class VideoFixtures {
  /// Video kung fu base
  static Map<String, dynamic> get kungFuBasic => {
        'id': 'video_kungfu_001',
        'title': 'Kung Fu - Posizioni Base',
        'discipline': 'kung_fu',
        'duration_seconds': 300,
        'is_premium': false,
        'has_skeleton': true,
        'languages': ['it', 'en', 'zh'],
      };

  /// Video tai chi premium
  static Map<String, dynamic> get taiChiPremium => {
        'id': 'video_taichi_001',
        'title': 'Tai Chi - 24 Forme',
        'discipline': 'tai_chi',
        'duration_seconds': 1200,
        'is_premium': true,
        'has_skeleton': true,
        'languages': ['it', 'en', 'zh', 'jp'],
      };

  /// Video senza skeleton
  static Map<String, dynamic> get noSkeleton => {
        'id': 'video_intro_001',
        'title': 'Introduzione alle Arti Marziali',
        'discipline': 'general',
        'duration_seconds': 180,
        'is_premium': false,
        'has_skeleton': false,
        'languages': ['it'],
      };
}
