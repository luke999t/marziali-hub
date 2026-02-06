/// 🎓 AI_MODULE: EnhancedPlayerEntitiesTest
/// 🎓 AI_DESCRIPTION: Test Entity Player Enhanced - Skeleton, Chapters, Quality, Settings
/// 🎓 AI_BUSINESS: Validazione strutture dati per player avanzato
/// 🎓 AI_TEACHING: Test unitari puri per entity (no backend necessario)
///
/// NOTA: Entity test sono test unitari puri - NON richiedono backend
/// Testano costruttori, metodi, Equatable, serializzazione

import 'package:flutter_test/flutter_test.dart';

import 'package:martial_arts_streaming/features/player/domain/entities/skeleton_data_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/chapter_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/video_quality_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/playback_settings_entity.dart';

void main() {
  // ==========================================================================
  // SKELETON DATA ENTITY TESTS
  // ==========================================================================
  group('SkeletonLandmark Entity', () {
    test('costruttore con tutti i parametri', () {
      const landmark = SkeletonLandmark(
        x: 0.5,
        y: 0.3,
        z: 0.1,
        visibility: 0.95,
      );

      expect(landmark.x, equals(0.5));
      expect(landmark.y, equals(0.3));
      expect(landmark.z, equals(0.1));
      expect(landmark.visibility, equals(0.95));
    });

    test('fromJson crea istanza corretta', () {
      final json = {
        'x': 0.5,
        'y': 0.3,
        'z': 0.1,
        'visibility': 0.95,
      };

      final landmark = SkeletonLandmark.fromJson(json);

      expect(landmark.x, equals(0.5));
      expect(landmark.y, equals(0.3));
      expect(landmark.z, equals(0.1));
      expect(landmark.visibility, equals(0.95));
    });

    test('toJson serializza correttamente', () {
      const landmark = SkeletonLandmark(
        x: 0.5,
        y: 0.3,
        z: 0.1,
        visibility: 0.95,
      );

      final json = landmark.toJson();

      expect(json['x'], equals(0.5));
      expect(json['y'], equals(0.3));
      expect(json['z'], equals(0.1));
      expect(json['visibility'], equals(0.95));
    });

    test('lerp interpola correttamente tra due landmark', () {
      const a = SkeletonLandmark(x: 0.0, y: 0.0, z: 0.0, visibility: 1.0);
      const b = SkeletonLandmark(x: 1.0, y: 1.0, z: 1.0, visibility: 0.5);

      final mid = SkeletonLandmark.lerp(a, b, 0.5);

      expect(mid.x, equals(0.5));
      expect(mid.y, equals(0.5));
      expect(mid.z, equals(0.5));
      expect(mid.visibility, equals(0.75));
    });

    test('Equatable: due landmark uguali', () {
      const landmark1 = SkeletonLandmark(x: 0.5, y: 0.3, z: 0.1, visibility: 0.95);
      const landmark2 = SkeletonLandmark(x: 0.5, y: 0.3, z: 0.1, visibility: 0.95);

      expect(landmark1, equals(landmark2));
    });

    test('Equatable: due landmark diversi', () {
      const landmark1 = SkeletonLandmark(x: 0.5, y: 0.3, z: 0.1, visibility: 0.95);
      const landmark2 = SkeletonLandmark(x: 0.6, y: 0.3, z: 0.1, visibility: 0.95);

      expect(landmark1, isNot(equals(landmark2)));
    });
  });

  group('HandLandmark Entity', () {
    test('costruttore con parametri corretti', () {
      const hand = HandLandmark(
        index: 0,
        name: 'wrist',
        x: 0.5,
        y: 0.5,
        z: 0.0,
        visibility: 1.0,
      );

      expect(hand.index, equals(0));
      expect(hand.name, equals('wrist'));
      expect(hand.x, equals(0.5));
    });

    test('fromJson crea istanza corretta', () {
      final json = {
        'index': 4,
        'name': 'thumb_tip',
        'x': 0.3,
        'y': 0.4,
        'z': 0.1,
        'visibility': 0.9,
      };

      final hand = HandLandmark.fromJson(json);

      expect(hand.index, equals(4));
      expect(hand.name, equals('thumb_tip'));
      expect(hand.x, equals(0.3));
    });
  });

  group('SkeletonFrame Entity', () {
    test('costruttore con pose landmarks', () {
      const landmarks = [
        SkeletonLandmark(x: 0.5, y: 0.1, z: 0.0, visibility: 1.0),
        SkeletonLandmark(x: 0.5, y: 0.2, z: 0.0, visibility: 1.0),
      ];

      final frame = SkeletonFrame(
        timestamp: const Duration(seconds: 5),
        poseLandmarks: landmarks,
      );

      expect(frame.timestamp.inSeconds, equals(5));
      expect(frame.poseLandmarks.length, equals(2));
      expect(frame.leftHandLandmarks, isNull);
      expect(frame.rightHandLandmarks, isNull);
    });

    test('fromJson con hand landmarks', () {
      final json = {
        'timestamp_ms': 5000,
        'pose_landmarks': [
          {'x': 0.5, 'y': 0.1, 'z': 0.0, 'visibility': 1.0},
        ],
        'left_hand': [
          {'index': 0, 'name': 'wrist', 'x': 0.3, 'y': 0.5, 'z': 0.0, 'visibility': 1.0},
        ],
        'right_hand': [
          {'index': 0, 'name': 'wrist', 'x': 0.7, 'y': 0.5, 'z': 0.0, 'visibility': 1.0},
        ],
        'angles': {'elbow_left': 90.0, 'elbow_right': 85.0},
      };

      final frame = SkeletonFrame.fromJson(json);

      expect(frame.timestamp.inMilliseconds, equals(5000));
      expect(frame.poseLandmarks.length, equals(1));
      expect(frame.leftHandLandmarks, isNotNull);
      expect(frame.leftHandLandmarks!.length, equals(1));
      expect(frame.rightHandLandmarks, isNotNull);
      expect(frame.angles, isNotNull);
      expect(frame.angles!['elbow_left'], equals(90.0));
    });
  });

  group('SkeletonData Entity', () {
    late List<SkeletonFrame> frames;
    late SkeletonData skeletonData;

    setUp(() {
      frames = [
        SkeletonFrame(
          timestamp: Duration.zero,
          poseLandmarks: const [
            SkeletonLandmark(x: 0.5, y: 0.1, z: 0.0, visibility: 1.0),
          ],
        ),
        SkeletonFrame(
          timestamp: const Duration(seconds: 1),
          poseLandmarks: const [
            SkeletonLandmark(x: 0.6, y: 0.2, z: 0.0, visibility: 1.0),
          ],
        ),
        SkeletonFrame(
          timestamp: const Duration(seconds: 2),
          poseLandmarks: const [
            SkeletonLandmark(x: 0.7, y: 0.3, z: 0.0, visibility: 1.0),
          ],
        ),
      ];

      skeletonData = SkeletonData(
        videoId: 'test-video',
        fps: 30.0,
        totalFrames: 3,
        frames: frames,
      );
    });

    test('costruttore con parametri validi', () {
      expect(skeletonData.videoId, equals('test-video'));
      expect(skeletonData.fps, equals(30.0));
      expect(skeletonData.totalFrames, equals(3));
      expect(skeletonData.frames.length, equals(3));
    });

    test('getFrameAt ritorna frame corretto', () {
      final frame = skeletonData.getFrameAt(const Duration(seconds: 1));

      expect(frame, isNotNull);
      expect(frame!.timestamp.inSeconds, equals(1));
    });

    test('getFrameAt ritorna null per timestamp fuori range', () {
      final frame = skeletonData.getFrameAt(const Duration(seconds: 10));

      expect(frame, isNull);
    });

    test('getInterpolatedFrame interpola tra due frame', () {
      // A 0.5 secondi, dovrebbe interpolare tra frame 0 (0s) e frame 1 (1s)
      final interpolated = skeletonData.getInterpolatedFrame(
        const Duration(milliseconds: 500),
      );

      expect(interpolated, isNotNull);
      // Verifica che x sia interpolato (0.5 a 0s, 0.6 a 1s -> ~0.55 a 0.5s)
      expect(interpolated!.poseLandmarks[0].x, closeTo(0.55, 0.01));
    });

    test('duration restituisce durata corretta', () {
      expect(skeletonData.duration.inSeconds, equals(2));
    });

    test('hasFrames è true con frame', () {
      expect(skeletonData.hasFrames, isTrue);
    });

    test('hasFrames è false senza frame', () {
      final emptyData = SkeletonData(
        videoId: 'empty',
        fps: 30.0,
        totalFrames: 0,
        frames: [],
      );

      expect(emptyData.hasFrames, isFalse);
    });
  });

  // ==========================================================================
  // CHAPTER ENTITY TESTS
  // ==========================================================================
  group('Chapter Entity', () {
    test('costruttore con parametri obbligatori', () {
      const chapter = Chapter(
        id: 'ch-1',
        title: 'Riscaldamento',
        startTime: Duration(seconds: 0),
        endTime: Duration(minutes: 5),
      );

      expect(chapter.id, equals('ch-1'));
      expect(chapter.title, equals('Riscaldamento'));
      expect(chapter.startTime.inSeconds, equals(0));
      expect(chapter.endTime.inMinutes, equals(5));
      expect(chapter.type, equals(ChapterType.regular));
    });

    test('costruttore con tutti i parametri', () {
      const chapter = Chapter(
        id: 'ch-intro',
        title: 'Intro',
        startTime: Duration(seconds: 0),
        endTime: Duration(seconds: 30),
        thumbnailUrl: 'https://cdn.example.com/thumb.jpg',
        description: 'Introduzione al corso',
        type: ChapterType.intro,
      );

      expect(chapter.type, equals(ChapterType.intro));
      expect(chapter.thumbnailUrl, isNotNull);
      expect(chapter.description, isNotNull);
    });

    test('containsPosition ritorna true per posizione valida', () {
      const chapter = Chapter(
        id: 'ch-1',
        title: 'Test',
        startTime: Duration(seconds: 10),
        endTime: Duration(seconds: 30),
      );

      expect(chapter.containsPosition(const Duration(seconds: 15)), isTrue);
      expect(chapter.containsPosition(const Duration(seconds: 10)), isTrue);
      expect(chapter.containsPosition(const Duration(seconds: 29)), isTrue);
    });

    test('containsPosition ritorna false per posizione fuori range', () {
      const chapter = Chapter(
        id: 'ch-1',
        title: 'Test',
        startTime: Duration(seconds: 10),
        endTime: Duration(seconds: 30),
      );

      expect(chapter.containsPosition(const Duration(seconds: 5)), isFalse);
      expect(chapter.containsPosition(const Duration(seconds: 30)), isFalse);
      expect(chapter.containsPosition(const Duration(seconds: 35)), isFalse);
    });

    test('duration restituisce durata corretta', () {
      const chapter = Chapter(
        id: 'ch-1',
        title: 'Test',
        startTime: Duration(seconds: 10),
        endTime: Duration(seconds: 30),
      );

      expect(chapter.duration.inSeconds, equals(20));
    });

    test('fromJson crea istanza corretta', () {
      final json = {
        'id': 'ch-1',
        'title': 'Test Chapter',
        'start_time_ms': 10000,
        'end_time_ms': 30000,
        'thumbnail_url': 'https://example.com/thumb.jpg',
        'type': 'highlight',
      };

      final chapter = Chapter.fromJson(json);

      expect(chapter.id, equals('ch-1'));
      expect(chapter.title, equals('Test Chapter'));
      expect(chapter.startTime.inMilliseconds, equals(10000));
      expect(chapter.type, equals(ChapterType.highlight));
    });
  });

  group('VideoChapters Entity', () {
    late VideoChapters videoChapters;

    setUp(() {
      videoChapters = VideoChapters(
        videoId: 'test-video',
        chapters: const [
          Chapter(
            id: 'ch-1',
            title: 'Intro',
            startTime: Duration(seconds: 0),
            endTime: Duration(seconds: 30),
            type: ChapterType.intro,
          ),
          Chapter(
            id: 'ch-2',
            title: 'Riscaldamento',
            startTime: Duration(seconds: 30),
            endTime: Duration(minutes: 5),
          ),
          Chapter(
            id: 'ch-3',
            title: 'Tecniche',
            startTime: Duration(minutes: 5),
            endTime: Duration(minutes: 20),
          ),
          Chapter(
            id: 'ch-4',
            title: 'Credits',
            startTime: Duration(minutes: 20),
            endTime: Duration(minutes: 21),
            type: ChapterType.credits,
          ),
        ],
      );
    });

    test('getChapterAt ritorna chapter corretto', () {
      final chapter = videoChapters.getChapterAt(const Duration(seconds: 15));

      expect(chapter, isNotNull);
      expect(chapter!.id, equals('ch-1'));
    });

    test('getChapterAt ritorna null per posizione senza chapter', () {
      // Se c'è un gap tra chapters
      final emptyChapters = VideoChapters(
        videoId: 'test',
        chapters: const [
          Chapter(
            id: 'ch-1',
            title: 'Chapter 1',
            startTime: Duration(seconds: 0),
            endTime: Duration(seconds: 10),
          ),
        ],
      );

      final chapter = emptyChapters.getChapterAt(const Duration(seconds: 15));
      expect(chapter, isNull);
    });

    test('getNextChapter ritorna prossimo chapter', () {
      final next = videoChapters.getNextChapter(const Duration(seconds: 15));

      expect(next, isNotNull);
      expect(next!.id, equals('ch-2'));
    });

    test('getNextChapter ritorna null se è ultimo chapter', () {
      final next = videoChapters.getNextChapter(const Duration(minutes: 20, seconds: 30));

      expect(next, isNull);
    });

    test('getPreviousChapter ritorna chapter precedente', () {
      final prev = videoChapters.getPreviousChapter(const Duration(minutes: 6));

      expect(prev, isNotNull);
      expect(prev!.id, equals('ch-2'));
    });

    test('getPreviousChapter ritorna null se è primo chapter', () {
      final prev = videoChapters.getPreviousChapter(const Duration(seconds: 10));

      expect(prev, isNull);
    });

    test('hasChapters è true', () {
      expect(videoChapters.hasChapters, isTrue);
    });

    test('chapterCount ritorna conteggio corretto', () {
      expect(videoChapters.chapterCount, equals(4));
    });
  });

  group('SkipSegment Entity', () {
    test('costruttore con parametri corretti', () {
      const segment = SkipSegment(
        startTime: Duration(seconds: 0),
        endTime: Duration(seconds: 30),
        skipToPosition: Duration(seconds: 30),
        label: 'Salta intro',
        type: SkipType.intro,
      );

      expect(segment.label, equals('Salta intro'));
      expect(segment.type, equals(SkipType.intro));
      expect(segment.autoSkip, isFalse);
    });

    test('containsPosition funziona correttamente', () {
      const segment = SkipSegment(
        startTime: Duration(seconds: 0),
        endTime: Duration(seconds: 30),
        skipToPosition: Duration(seconds: 30),
        label: 'Salta intro',
        type: SkipType.intro,
      );

      expect(segment.containsPosition(const Duration(seconds: 15)), isTrue);
      expect(segment.containsPosition(const Duration(seconds: 35)), isFalse);
    });

    test('fromJson con autoSkip', () {
      final json = {
        'start_time_ms': 0,
        'end_time_ms': 30000,
        'skip_to_ms': 30000,
        'label': 'Skip Credits',
        'type': 'credits',
        'auto_skip': true,
      };

      final segment = SkipSegment.fromJson(json);

      expect(segment.type, equals(SkipType.credits));
      expect(segment.autoSkip, isTrue);
    });
  });

  // ==========================================================================
  // VIDEO QUALITY ENTITY TESTS
  // ==========================================================================
  group('VideoQuality Entity', () {
    test('costruttore con parametri corretti', () {
      const quality = VideoQuality(
        level: VideoQualityLevel.fullHd,
        streamUrl: 'https://cdn.example.com/1080p.m3u8',
        resolution: '1920x1080',
        bitrate: 5000000,
      );

      expect(quality.level, equals(VideoQualityLevel.fullHd));
      expect(quality.resolution, equals('1920x1080'));
      expect(quality.bitrate, equals(5000000));
    });

    test('displayName ritorna nome leggibile', () {
      const quality = VideoQuality(
        level: VideoQualityLevel.ultraHd,
        streamUrl: 'https://cdn.example.com/4k.m3u8',
        resolution: '3840x2160',
        bitrate: 15000000,
      );

      expect(quality.displayName, equals('4K Ultra HD'));
    });

    test('fromJson crea istanza corretta', () {
      final json = {
        'level': 'high',
        'stream_url': 'https://cdn.example.com/720p.m3u8',
        'resolution': '1280x720',
        'bitrate': 2500000,
      };

      final quality = VideoQuality.fromJson(json);

      expect(quality.level, equals(VideoQualityLevel.high));
      expect(quality.resolution, equals('1280x720'));
    });
  });

  group('AvailableQualities Entity', () {
    late AvailableQualities qualities;

    setUp(() {
      qualities = AvailableQualities(
        videoId: 'test-video',
        qualities: const [
          VideoQuality(
            level: VideoQualityLevel.auto,
            streamUrl: 'https://cdn.example.com/auto.m3u8',
          ),
          VideoQuality(
            level: VideoQualityLevel.low,
            streamUrl: 'https://cdn.example.com/360p.m3u8',
            resolution: '640x360',
            bitrate: 500000,
          ),
          VideoQuality(
            level: VideoQualityLevel.medium,
            streamUrl: 'https://cdn.example.com/480p.m3u8',
            resolution: '854x480',
            bitrate: 1000000,
          ),
          VideoQuality(
            level: VideoQualityLevel.high,
            streamUrl: 'https://cdn.example.com/720p.m3u8',
            resolution: '1280x720',
            bitrate: 2500000,
          ),
          VideoQuality(
            level: VideoQualityLevel.fullHd,
            streamUrl: 'https://cdn.example.com/1080p.m3u8',
            resolution: '1920x1080',
            bitrate: 5000000,
          ),
        ],
      );
    });

    test('getQuality ritorna qualità corretta', () {
      final hd = qualities.getQuality(VideoQualityLevel.fullHd);

      expect(hd, isNotNull);
      expect(hd!.resolution, equals('1920x1080'));
    });

    test('getQuality ritorna null per qualità non disponibile', () {
      final uhd = qualities.getQuality(VideoQualityLevel.ultraHd);

      expect(uhd, isNull);
    });

    test('bestAvailable ritorna qualità migliore', () {
      final best = qualities.bestAvailable;

      expect(best, isNotNull);
      expect(best!.level, equals(VideoQualityLevel.fullHd));
    });

    test('hasQuality verifica disponibilità', () {
      expect(qualities.hasQuality(VideoQualityLevel.high), isTrue);
      expect(qualities.hasQuality(VideoQualityLevel.ultraHd), isFalse);
    });

    test('getBestForBandwidth sceglie qualità appropriata', () {
      // 3 Mbps bandwidth - dovrebbe scegliere 720p (2.5 Mbps)
      final selected = qualities.getBestForBandwidth(3000000);

      expect(selected, isNotNull);
      expect(selected!.level, equals(VideoQualityLevel.high));
    });

    test('getBestForBandwidth sceglie qualità più bassa per banda limitata', () {
      // 600 Kbps bandwidth - dovrebbe scegliere 360p (500 Kbps)
      final selected = qualities.getBestForBandwidth(600000);

      expect(selected, isNotNull);
      expect(selected!.level, equals(VideoQualityLevel.low));
    });
  });

  // ==========================================================================
  // PLAYBACK SETTINGS ENTITY TESTS
  // ==========================================================================
  group('PlaybackSettings Entity', () {
    test('costruttore con valori default', () {
      const settings = PlaybackSettings();

      expect(settings.playbackSpeed, equals(1.0));
      expect(settings.preferredQuality, equals(VideoQualityLevel.auto));
      expect(settings.autoPlayNextEpisode, isTrue);
      expect(settings.skipIntro, isFalse);
      expect(settings.skipCredits, isFalse);
    });

    test('costruttore con valori custom', () {
      const settings = PlaybackSettings(
        playbackSpeed: 1.5,
        preferredQuality: VideoQualityLevel.fullHd,
        autoPlayNextEpisode: false,
        skipIntro: true,
        skipCredits: true,
        rememberPosition: true,
        showSkeletonOverlay: true,
      );

      expect(settings.playbackSpeed, equals(1.5));
      expect(settings.preferredQuality, equals(VideoQualityLevel.fullHd));
      expect(settings.autoPlayNextEpisode, isFalse);
      expect(settings.skipIntro, isTrue);
      expect(settings.showSkeletonOverlay, isTrue);
    });

    test('copyWith modifica solo parametri specificati', () {
      const original = PlaybackSettings(
        playbackSpeed: 1.0,
        preferredQuality: VideoQualityLevel.auto,
      );

      final updated = original.copyWith(
        playbackSpeed: 2.0,
      );

      expect(updated.playbackSpeed, equals(2.0));
      expect(updated.preferredQuality, equals(VideoQualityLevel.auto));
    });

    test('fromJson crea istanza corretta', () {
      final json = {
        'playback_speed': 1.25,
        'preferred_quality': 'high',
        'auto_play_next': false,
        'skip_intro': true,
      };

      final settings = PlaybackSettings.fromJson(json);

      expect(settings.playbackSpeed, equals(1.25));
      expect(settings.preferredQuality, equals(VideoQualityLevel.high));
      expect(settings.autoPlayNextEpisode, isFalse);
      expect(settings.skipIntro, isTrue);
    });

    test('toJson serializza correttamente', () {
      const settings = PlaybackSettings(
        playbackSpeed: 1.5,
        preferredQuality: VideoQualityLevel.fullHd,
        skipIntro: true,
      );

      final json = settings.toJson();

      expect(json['playback_speed'], equals(1.5));
      expect(json['preferred_quality'], equals('fullHd'));
      expect(json['skip_intro'], isTrue);
    });
  });

  group('SubtitleSettings Entity', () {
    test('costruttore con valori default', () {
      const settings = SubtitleSettings();

      expect(settings.fontSize, equals(16.0));
      expect(settings.language, equals('off'));
    });

    test('fromJson con colori', () {
      final json = {
        'font_size': 20.0,
        'font_color': 0xFFFFFFFF,
        'background_color': 0x80000000,
        'language': 'Italian',
      };

      final settings = SubtitleSettings.fromJson(json);

      expect(settings.fontSize, equals(20.0));
      expect(settings.language, equals('Italian'));
    });
  });

  group('SkeletonOverlaySettings Entity', () {
    test('costruttore con valori default', () {
      const settings = SkeletonOverlaySettings();

      expect(settings.opacity, equals(0.8));
      expect(settings.showHands, isTrue);
      expect(settings.showAngles, isFalse);
    });

    test('copyWith modifica parametri', () {
      const original = SkeletonOverlaySettings();

      final updated = original.copyWith(
        showAngles: true,
        lineWidth: 3.0,
      );

      expect(updated.showAngles, isTrue);
      expect(updated.lineWidth, equals(3.0));
      expect(updated.showHands, isTrue); // Non modificato
    });
  });

  group('GestureSettings Entity', () {
    test('costruttore con valori default', () {
      const settings = GestureSettings();

      expect(settings.doubleTapToSeekEnabled, isTrue);
      expect(settings.doubleTapSeekDuration.inSeconds, equals(10));
      expect(settings.swipeToAdjustVolumeEnabled, isTrue);
      expect(settings.swipeToAdjustBrightnessEnabled, isTrue);
      expect(settings.longPressSpeedEnabled, isTrue);
      expect(settings.longPressSpeed, equals(2.0));
    });

    test('copyWith modifica parametri', () {
      const original = GestureSettings();

      final updated = original.copyWith(
        doubleTapSeekDuration: const Duration(seconds: 15),
        longPressSpeed: 1.5,
      );

      expect(updated.doubleTapSeekDuration.inSeconds, equals(15));
      expect(updated.longPressSpeed, equals(1.5));
    });
  });
}
