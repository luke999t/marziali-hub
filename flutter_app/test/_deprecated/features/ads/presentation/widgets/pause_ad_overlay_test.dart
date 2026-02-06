/// ================================================================================
/// AI_MODULE: PauseAdOverlay Widget Tests
/// AI_DESCRIPTION: Test suite per PauseAdOverlay widget
/// AI_BUSINESS: Verifica UI e accessibility dell'overlay pause ads
/// AI_TEACHING: Widget testing, golden tests, accessibility
///
/// COVERAGE_TARGET: >= 90%
///
/// TEST CASES:
/// - Renders suggested video card
/// - Renders sponsor ad card
/// - Renders both cards in 50/50 layout
/// - Handles missing content gracefully
/// - Calls onResume when backdrop tapped
/// - Calls onSuggestedVideoClick when video tapped
/// - Accessibility labels present
/// ================================================================================

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:mocktail/mocktail.dart';

import 'package:media_center_app/features/ads/domain/entities/pause_ad.dart';
import 'package:media_center_app/features/ads/presentation/bloc/pause_ad_bloc.dart';
import 'package:media_center_app/features/ads/presentation/widgets/pause_ad_overlay.dart';

// Mock classes
class MockPauseAdBloc extends MockBloc<PauseAdEvent, PauseAdState>
    implements PauseAdBloc {}

class FakePauseAdEvent extends Fake implements PauseAdEvent {}

class FakePauseAdState extends Fake implements PauseAdState {}

void main() {
  late MockPauseAdBloc mockBloc;

  setUpAll(() {
    registerFallbackValue(FakePauseAdEvent());
    registerFallbackValue(FakePauseAdState());
  });

  setUp(() {
    mockBloc = MockPauseAdBloc();
  });

  // Test data
  final testPauseAd = PauseAd(
    suggestedVideo: const SuggestedVideo(
      id: 'suggested-456',
      title: 'Kata Heian Nidan',
      thumbnailUrl: 'https://example.com/thumb.jpg',
      duration: 185,
      maestroName: 'Maestro Chen',
      style: 'Karate Shotokan',
    ),
    sponsorAd: const SponsorAd(
      id: 'ad-001',
      advertiser: 'Decathlon Italia',
      title: 'Kimono Judo -30%',
      description: 'Offerta esclusiva',
      imageUrl: 'https://example.com/ad.jpg',
      clickUrl: 'https://decathlon.it/promo',
    ),
    impressionId: 'imp-uuid-123',
    showOverlay: true,
  );

  Widget buildTestWidget({
    required PauseAdState state,
    VoidCallback? onResume,
    void Function(String)? onSuggestedVideoClick,
  }) {
    when(() => mockBloc.state).thenReturn(state);
    whenListen(
      mockBloc,
      Stream<PauseAdState>.value(state),
      initialState: state,
    );

    return MaterialApp(
      home: Scaffold(
        body: BlocProvider<PauseAdBloc>.value(
          value: mockBloc,
          child: PauseAdOverlay(
            onResume: onResume ?? () {},
            onSuggestedVideoClick: onSuggestedVideoClick,
          ),
        ),
      ),
    );
  }

  group('PauseAdOverlay', () {
    group('Rendering', () {
      testWidgets('should render nothing when shouldShowOverlay is false', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.hidden,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));

        // Assert
        expect(find.text('Kata Heian Nidan'), findsNothing);
        expect(find.text('Kimono Judo -30%'), findsNothing);
      });

      testWidgets('should render suggested video when visible', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(find.text('Kata Heian Nidan'), findsOneWidget);
        expect(find.text('Maestro Chen • Karate Shotokan'), findsOneWidget);
        expect(find.text('Consigliato'), findsOneWidget);
      });

      testWidgets('should render sponsor ad when visible', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(find.text('Kimono Judo -30%'), findsOneWidget);
        expect(find.text('Decathlon Italia'), findsOneWidget);
        expect(find.text('Sponsor'), findsOneWidget);
        expect(find.text('Scopri di più'), findsOneWidget);
      });

      testWidgets('should render only suggested video when no sponsorAd', (tester) async {
        // Arrange
        final pauseAdWithoutSponsor = PauseAd(
          suggestedVideo: testPauseAd.suggestedVideo,
          impressionId: 'imp-123',
          showOverlay: true,
        );

        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: pauseAdWithoutSponsor,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(find.text('Kata Heian Nidan'), findsOneWidget);
        expect(find.text('Sponsor'), findsNothing);
      });

      testWidgets('should render only sponsor ad when no suggestedVideo', (tester) async {
        // Arrange
        final pauseAdWithoutVideo = PauseAd(
          sponsorAd: testPauseAd.sponsorAd,
          impressionId: 'imp-123',
          showOverlay: true,
        );

        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: pauseAdWithoutVideo,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(find.text('Kimono Judo -30%'), findsOneWidget);
        expect(find.text('Consigliato'), findsNothing);
      });

      testWidgets('should display formatted duration', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert - 185 seconds = 3:05
        expect(find.text('3:05'), findsOneWidget);
      });

      testWidgets('should display resume hint text', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(find.text('Tocca fuori per riprendere'), findsOneWidget);
      });
    });

    group('Interactions', () {
      testWidgets('should call onResume when close button tapped', (tester) async {
        // Arrange
        var resumeCalled = false;
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(
          state: state,
          onResume: () => resumeCalled = true,
        ));
        await tester.pump();

        // Find close button by icon
        final closeButton = find.byIcon(Icons.close);
        await tester.tap(closeButton);

        // Assert
        expect(resumeCalled, true);
      });

      testWidgets('should dispatch NavigateToSuggestedVideoEvent when video tapped', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        await tester.tap(find.text('Kata Heian Nidan'));

        // Assert
        verify(() => mockBloc.add(any(that: isA<NavigateToSuggestedVideoEvent>()))).called(1);
      });

      testWidgets('should dispatch OpenSponsorUrlEvent when sponsor ad tapped', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        await tester.tap(find.text('Kimono Judo -30%'));

        // Assert
        verify(() => mockBloc.add(any(that: isA<OpenSponsorUrlEvent>()))).called(1);
      });

      testWidgets('should call onSuggestedVideoClick callback', (tester) async {
        // Arrange
        String? clickedVideoId;
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(
          state: state,
          onSuggestedVideoClick: (id) => clickedVideoId = id,
        ));
        await tester.pump();

        await tester.tap(find.text('Kata Heian Nidan'));

        // Assert
        expect(clickedVideoId, 'suggested-456');
      });
    });

    group('Accessibility', () {
      testWidgets('should have accessibility label on overlay', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(
          find.bySemanticsLabel('Pause overlay con suggerimenti'),
          findsOneWidget,
        );
      });

      testWidgets('should have accessibility label on close button', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(
          find.bySemanticsLabel('Chiudi overlay'),
          findsOneWidget,
        );
      });

      testWidgets('should have accessibility label on suggested video', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(
          find.bySemanticsLabel('Guarda Kata Heian Nidan'),
          findsOneWidget,
        );
      });

      testWidgets('should have accessibility label on sponsor ad', (tester) async {
        // Arrange
        final state = PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        );

        // Act
        await tester.pumpWidget(buildTestWidget(state: state));
        await tester.pump();

        // Assert
        expect(
          find.bySemanticsLabel(RegExp(r'Visita Decathlon Italia')),
          findsOneWidget,
        );
      });
    });
  });
}
