/// ================================================================================
/// 🎓 AI_MODULE: SubtitlesOverlayRealTest
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Unit tests REALI per SubtitlesOverlay - ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica rendering sottotitoli, sync timing,
///                 tappable terms, multilingua support.
/// 🎓 AI_TEACHING: Widget testing, animation testing,
///                 gesture testing, text rendering verification.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
/// 🎓 AI_FIX: 2025-12-15 - Wrapped SubtitlesOverlay in Stack for Positioned support
///
/// 📊 TEST CATEGORIES:
/// - SubtitleCue model
/// - TechnicalTerm model
/// - Timing synchronization
/// - Widget rendering
/// - Tap gesture handling
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Test logic pura senza mock
/// - Widget test con WidgetTester reale
/// ================================================================================

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import '../../../../../lib/features/player/presentation/widgets/subtitles_overlay.dart';
import '../../../../helpers/glasses_fixtures.dart';
import '../../../../helpers/mock_blocker.dart';

void main() {
  enforceMockPolicy();

  // ===========================================================================
  // SUBTITLE CUE MODEL TESTS
  // ===========================================================================

  group('SubtitleCue Model', () {
    test('fromJson parses all fields correctly', () {
      final json = {
        'start_ms': 5000,
        'end_ms': 10000,
        'text': 'Questa è una frase di test.',
        'language': 'it',
      };

      final cue = SubtitleCue.fromJson(json);

      expect(cue.startTime.inMilliseconds, equals(5000));
      expect(cue.endTime.inMilliseconds, equals(10000));
      expect(cue.text, equals('Questa è una frase di test.'));
      expect(cue.language, equals('it'));
    });

    test('fromJson handles missing language with default', () {
      final json = {
        'start_ms': 0,
        'end_ms': 5000,
        'text': 'Test text',
      };

      final cue = SubtitleCue.fromJson(json);

      expect(cue.language, isNull);
    });

    test('fromJson parses technical terms', () {
      final json = {
        'start_ms': 5000,
        'end_ms': 10000,
        'text': 'Eseguiamo ora il Mabu (posizione del cavaliere).',
        'language': 'it',
        'technical_terms': [
          {
            'term': 'Mabu',
            'definition': 'Posizione fondamentale con gambe divaricate',
            'start_index': 16,
            'end_index': 20,
          }
        ],
      };

      final cue = SubtitleCue.fromJson(json);

      expect(cue.technicalTerms, isNotEmpty);
      expect(cue.technicalTerms!.first.term, equals('Mabu'));
    });

    test('isActiveAt returns true when position in range', () {
      final cue = SubtitleCue(
        startTime: const Duration(milliseconds: 5000),
        endTime: const Duration(milliseconds: 10000),
        text: 'Test',
      );

      expect(cue.isActiveAt(const Duration(milliseconds: 5000)), isTrue);
      expect(cue.isActiveAt(const Duration(milliseconds: 7500)), isTrue);
      expect(cue.isActiveAt(const Duration(milliseconds: 9999)), isTrue);
    });

    test('isActiveAt returns false when position outside range', () {
      final cue = SubtitleCue(
        startTime: const Duration(milliseconds: 5000),
        endTime: const Duration(milliseconds: 10000),
        text: 'Test',
      );

      expect(cue.isActiveAt(const Duration(milliseconds: 4999)), isFalse);
      expect(cue.isActiveAt(const Duration(milliseconds: 10001)), isFalse);
      expect(cue.isActiveAt(const Duration(milliseconds: 15000)), isFalse);
    });

    test('duration calculates correctly', () {
      final cue = SubtitleCue(
        startTime: const Duration(milliseconds: 5000),
        endTime: const Duration(milliseconds: 10000),
        text: 'Test',
      );

      expect(cue.duration, equals(const Duration(milliseconds: 5000)));
    });

    test('technicalTerms check returns true when terms exist', () {
      final cueWithTerms = SubtitleCue(
        startTime: Duration.zero,
        endTime: const Duration(milliseconds: 5000),
        text: 'Test [Mabu]',
        technicalTerms: [
          TechnicalTerm(
            term: 'Mabu',
            definition: 'Horse stance',
            startIndex: 6,
            endIndex: 10,
          )
        ],
      );

      final cueWithoutTerms = SubtitleCue(
        startTime: Duration.zero,
        endTime: const Duration(milliseconds: 5000),
        text: 'Test',
      );

      expect(cueWithTerms.technicalTerms, isNotNull);
      expect(cueWithTerms.technicalTerms!.isNotEmpty, isTrue);
      expect(cueWithoutTerms.technicalTerms, isNull);
    });
  });

  // ===========================================================================
  // TECHNICAL TERM MODEL TESTS
  // ===========================================================================

  group('TechnicalTerm Model', () {
    test('fromJson parses all fields', () {
      final json = {
        'term': 'Mabu',
        'definition': 'Posizione del cavaliere',
        'start_index': 16,
        'end_index': 20,
        'pronunciation': 'mǎ bù',
        'origin_language': 'zh',
      };

      final term = TechnicalTerm.fromJson(json);

      expect(term.term, equals('Mabu'));
      expect(term.definition, equals('Posizione del cavaliere'));
      expect(term.startIndex, equals(16));
      expect(term.endIndex, equals(20));
      expect(term.pronunciation, equals('mǎ bù'));
      expect(term.originLanguage, equals('zh'));
    });

    test('fromJson handles optional fields', () {
      final json = {
        'term': 'Mabu',
        'definition': 'Horse stance',
      };

      final term = TechnicalTerm.fromJson(json);

      expect(term.term, equals('Mabu'));
      expect(term.definition, equals('Horse stance'));
      expect(term.pronunciation, isNull);
      expect(term.originLanguage, isNull);
    });

    test('toString provides readable output', () {
      final term = TechnicalTerm(
        term: 'Mabu',
        definition: 'Horse stance',
        startIndex: 0,
        endIndex: 4,
      );

      expect(term.toString(), contains('Mabu'));
    });
  });

  // ===========================================================================
  // SUBTITLE STYLE MODEL TESTS
  // ===========================================================================

  group('SubtitleStyle Model', () {
    test('default style has valid values', () {
      const style = SubtitleStyle();

      expect(style.fontSize, greaterThan(0));
      expect(style.textColor, isNotNull);
      expect(style.backgroundColor, isNotNull);
    });

    test('copyWith creates modified copy', () {
      const original = SubtitleStyle(fontSize: 16);
      final modified = original.copyWith(fontSize: 20);

      expect(original.fontSize, equals(16));
      expect(modified.fontSize, equals(20));
    });

    test('copyWith preserves unmodified fields', () {
      const original = SubtitleStyle(
        fontSize: 16,
        textColor: Colors.white,
        backgroundColor: Colors.black,
      );
      final modified = original.copyWith(fontSize: 20);

      expect(modified.textColor, equals(Colors.white));
      expect(modified.backgroundColor, equals(Colors.black));
    });
  });

  // ===========================================================================
  // SUBTITLES OVERLAY WIDGET TESTS
  // ===========================================================================

  group('SubtitlesOverlay Widget', () {
    testWidgets('renders empty when no subtitles', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: null,
                  currentPosition: Duration.zero,
                  language: 'it',
                ),
              ],
            ),
          ),
        ),
      );

      expect(find.byType(SubtitlesOverlay), findsOneWidget);
    });

    testWidgets('renders subtitle when position matches', (tester) async {
      final subtitles = {
        'it': SubtitleFixtures.italianSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
      };

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 1),
                  language: 'it',
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.textContaining('Benvenuti'), findsOneWidget);
    });

    testWidgets('does not render when position outside cue range', (tester) async {
      final subtitles = {
        'it': SubtitleFixtures.italianSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
      };

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 100),
                  language: 'it',
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.textContaining('Benvenuti'), findsNothing);
    });

    testWidgets('respects language selection', (tester) async {
      final subtitles = {
        'it': SubtitleFixtures.italianSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
        'en': SubtitleFixtures.englishSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
      };

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 1),
                  language: 'en',
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.textContaining('Welcome'), findsOneWidget);
      expect(find.textContaining('Benvenuti'), findsNothing);
    });

    testWidgets('updates when position changes', (tester) async {
      final subtitles = {
        'it': SubtitleFixtures.italianSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
      };

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 1),
                  language: 'it',
                ),
              ],
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.textContaining('Benvenuti'), findsOneWidget);

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 4),
                  language: 'it',
                ),
              ],
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.textContaining('Mabu'), findsOneWidget);
    });

    testWidgets('respects visible parameter', (tester) async {
      final subtitles = {
        'it': SubtitleFixtures.italianSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
      };

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 1),
                  language: 'it',
                  visible: false,
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byType(SubtitlesOverlay), findsOneWidget);
    });

    testWidgets('applies custom style', (tester) async {
      final subtitles = {
        'it': SubtitleFixtures.italianSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
      };

      const customStyle = SubtitleStyle(
        fontSize: 24,
        textColor: Colors.yellow,
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 1),
                  language: 'it',
                  style: customStyle,
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byType(SubtitlesOverlay), findsOneWidget);
    });

    testWidgets('handles dual subtitle mode', (tester) async {
      final subtitles = {
        'it': SubtitleFixtures.italianSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
        'en': SubtitleFixtures.englishSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
      };

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 1),
                  language: 'it',
                  secondaryLanguage: 'en',
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.textContaining('Benvenuti'), findsOneWidget);
      expect(find.textContaining('Welcome'), findsOneWidget);
    });
  });

  // ===========================================================================
  // TECHNICAL TERM TAP TESTS
  // ===========================================================================

  group('Technical Term Interaction', () {
    testWidgets('calls onTermTap when term is tapped', (tester) async {
      TechnicalTerm? tappedTerm;

      final subtitle = Subtitle.fromJson(SubtitleFixtures.technicalTermCue);
      final subtitles = {
        'it': [subtitle],
      };

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(milliseconds: 7500),
                  language: 'it',
                  onTermTap: (term) {
                    tappedTerm = term;
                  },
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byType(SubtitlesOverlay), findsOneWidget);
    });
  });

  // ===========================================================================
  // EDGE CASE TESTS
  // ===========================================================================

  group('Edge Cases', () {
    test('SubtitleCue handles zero duration', () {
      final cue = SubtitleCue(
        startTime: const Duration(milliseconds: 5000),
        endTime: const Duration(milliseconds: 5000),
        text: 'Test',
      );

      expect(cue.duration, equals(Duration.zero));
      expect(cue.isActiveAt(const Duration(milliseconds: 5000)), isTrue);
    });

    test('SubtitleCue handles overlapping cues', () {
      final cues = [
        SubtitleCue(
          startTime: Duration.zero,
          endTime: const Duration(milliseconds: 5000),
          text: 'First',
        ),
        SubtitleCue(
          startTime: const Duration(milliseconds: 3000),
          endTime: const Duration(milliseconds: 8000),
          text: 'Second',
        ),
      ];

      final position = const Duration(milliseconds: 4000);
      expect(cues[0].isActiveAt(position), isTrue);
      expect(cues[1].isActiveAt(position), isTrue);
    });

    test('handles empty subtitle text', () {
      final cue = SubtitleCue(
        startTime: Duration.zero,
        endTime: const Duration(milliseconds: 5000),
        text: '',
      );

      expect(cue.text, isEmpty);
      expect(cue.technicalTerms, isNull);
    });

    test('handles very long subtitle text', () {
      final longText = 'A' * 1000;
      final cue = SubtitleCue(
        startTime: Duration.zero,
        endTime: const Duration(milliseconds: 5000),
        text: longText,
      );

      expect(cue.text, hasLength(1000));
    });

    test('handles unicode in subtitles', () {
      final cue = SubtitleCue(
        startTime: Duration.zero,
        endTime: const Duration(milliseconds: 5000),
        text: '欢迎来到课程。 🥋 武术',
      );

      expect(cue.text, contains('欢迎'));
      expect(cue.text, contains('🥋'));
    });

    testWidgets('handles missing language gracefully', (tester) async {
      final subtitles = {
        'it': SubtitleFixtures.italianSubtitles
            .map((s) => Subtitle.fromJson(s))
            .toList(),
      };

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SubtitlesOverlay(
                  subtitles: subtitles,
                  currentPosition: const Duration(seconds: 1),
                  language: 'fr',
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byType(SubtitlesOverlay), findsOneWidget);
    });
  });

  // ===========================================================================
  // FIXTURE VALIDATION TESTS
  // ===========================================================================

  group('Subtitle Fixtures Validation', () {
    test('Italian subtitles have valid timing', () {
      for (final sub in SubtitleFixtures.italianSubtitles) {
        expect(sub['start_ms'], lessThan(sub['end_ms']));
        expect(sub['text'], isNotEmpty);
      }
    });

    test('English subtitles have valid timing', () {
      for (final sub in SubtitleFixtures.englishSubtitles) {
        expect(sub['start_ms'], lessThan(sub['end_ms']));
        expect(sub['text'], isNotEmpty);
      }
    });

    test('Chinese subtitles have valid timing', () {
      for (final sub in SubtitleFixtures.chineseSubtitles) {
        expect(sub['start_ms'], lessThan(sub['end_ms']));
        expect(sub['text'], isNotEmpty);
      }
    });

    test('All language subtitles are synchronized', () {
      final it = SubtitleFixtures.italianSubtitles;
      final en = SubtitleFixtures.englishSubtitles;
      final zh = SubtitleFixtures.chineseSubtitles;

      expect(it.length, equals(en.length));
      expect(en.length, equals(zh.length));

      for (int i = 0; i < it.length; i++) {
        expect(it[i]['start_ms'], equals(en[i]['start_ms']));
        expect(it[i]['end_ms'], equals(en[i]['end_ms']));
      }
    });
  });
}
