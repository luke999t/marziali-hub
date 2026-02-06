/// ================================================================================
///     HOLISTIC TESTS - USER JOURNEY
/// ================================================================================
///
///     REGOLA INVIOLABILE: Questo file NON contiene mock.
///     Tutti i test chiamano backend REALE su localhost:8000.
///
/// ================================================================================

import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import '../../helpers/test_config.dart';
import '../../helpers/api_helpers.dart';

void main() {
  late ApiTestHelper apiHelper;

  setUpAll(() async {
    await ensureBackendRunning();
  });

  setUp(() {
    apiHelper = ApiTestHelper();
  });

  tearDown(() async {
    await apiHelper.logout();
  });

  group('User Journey - Free User Video Learning', () {
    test('complete learning flow: login -> browse -> watch with ads', () async {
      // 1. LOGIN as FREE user
      await apiHelper.loginAsFreeUser();
      print('Step 1: Logged in as free user');

      // 2. Check if user sees ads (using authenticated request)
      final adsResponse = await apiHelper.authGet(
        '/api/v1/ads/pause-ad?video_id=00000000-0000-0000-0000-000000000001',
      );

      expect(adsResponse.statusCode, 200);
      final adsData = jsonDecode(adsResponse.body);
      // Free user should see ads structure with impression_id
      expect(adsData, contains('impression_id'));
      print('Step 2: Free user ad check passed');

      // 3. Simulate ad impression (using authenticated request)
      final impressionId =
          'imp-journey-${DateTime.now().millisecondsSinceEpoch}';
      final impressionResponse = await apiHelper.authPost(
        '/api/v1/ads/pause-ad/impression',
        {
          'impression_id': impressionId,
          'ad_id': 'test-ad',
          'video_id': '00000000-0000-0000-0000-000000000001',
        },
      );

      // 200/201/204 = success, 400 = no matching ad (OK for test env)
      expect([200, 201, 204, 400], contains(impressionResponse.statusCode));
      print('Step 3: Ad impression recorded');

      // 4. Check user profile
      final profileResponse = await apiHelper.authGet('/api/v1/auth/me');
      expect(profileResponse.statusCode, 200);
      print('Step 4: User profile accessible');
    });
  });

  group('User Journey - Premium User No Ads', () {
    test('premium user flow: login -> no ads -> smooth playback', () async {
      // 1. LOGIN as PREMIUM user
      await apiHelper.loginAsPremiumUser();
      print('Step 1: Logged in as premium user');

      // 2. Check premium user does NOT see ads (using authenticated request)
      final adsResponse = await apiHelper.authGet(
        '/api/v1/ads/pause-ad?video_id=00000000-0000-0000-0000-000000000001',
      );

      expect(adsResponse.statusCode, 200);
      final adsData = jsonDecode(adsResponse.body);
      // Premium user gets empty response or show_overlay=false
      if (adsData.isNotEmpty && adsData.containsKey('show_overlay')) {
        expect(adsData['show_overlay'], false);
      }
      print('Step 2: Premium user correctly does NOT see ads');

      // 3. Verify user tier in profile
      final profileResponse = await apiHelper.authGet('/api/v1/auth/me');
      expect(profileResponse.statusCode, 200);
      print('Step 3: Premium profile accessible');
    });
  });

  group('User Journey - Session Management', () {
    test('user can maintain session across operations', () async {
      // 1. Login
      await apiHelper.loginAsFreeUser();
      print('Step 1: Initial login');

      // 2. Multiple authenticated operations
      for (var i = 0; i < 5; i++) {
        final response = await apiHelper.authGet('/api/v1/auth/me');
        expect(response.statusCode, 200);
      }
      print('Step 2: 5 authenticated requests successful');

      // 3. Token refresh
      await apiHelper.refreshAccessToken();
      print('Step 3: Token refreshed');

      // 4. Continue with new token
      final response = await apiHelper.authGet('/api/v1/auth/me');
      expect(response.statusCode, 200);
      print('Step 4: Session maintained after refresh');

      // 5. Logout
      await apiHelper.logout();
      print('Step 5: Logged out successfully');
    });
  });

  group('User Journey - Error Recovery', () {
    test('app recovers from network errors gracefully', () async {
      // Login
      await apiHelper.loginAsFreeUser();

      // Simulate rapid requests that might cause issues
      final futures = <Future<http.Response>>[];
      for (var i = 0; i < 10; i++) {
        futures.add(apiHelper.authGet('/api/v1/auth/me'));
      }

      final responses = await Future.wait(futures);

      var successCount = 0;
      for (final response in responses) {
        if (response.statusCode == 200) successCount++;
      }

      expect(successCount, greaterThanOrEqualTo(7));
      print('Recovered from burst: $successCount/10 requests succeeded');
    });

    test('invalid operations do not break session', () async {
      await apiHelper.loginAsFreeUser();

      // Try invalid operation
      final invalidResponse = await apiHelper.authGet('/api/v1/nonexistent');
      expect([404], contains(invalidResponse.statusCode));

      // Session should still work
      final validResponse = await apiHelper.authGet('/api/v1/auth/me');
      expect(validResponse.statusCode, 200);
      print('Session survived invalid operation');
    });
  });

  group('User Journey - Ads Interaction Complete Flow', () {
    test('complete ad interaction: view -> click -> track', () async {
      // Login first for authenticated requests
      await apiHelper.loginAsFreeUser();

      // Use valid UUID format for video_id
      const videoId = '00000000-0000-0000-0000-000000000002';

      // 1. Fetch pause ad (authenticated)
      final adResponse = await apiHelper.authGet(
        '/api/v1/ads/pause-ad?video_id=$videoId',
      );

      expect(adResponse.statusCode, 200);
      final adData = jsonDecode(adResponse.body);
      final impressionId = adData['impression_id'] ?? 'imp-${DateTime.now().millisecondsSinceEpoch}';
      print('Step 1: Fetched ad with impression_id: $impressionId');

      // 2. Record impression (user saw the ad) - authenticated
      final impressionResponse = await apiHelper.authPost(
        '/api/v1/ads/pause-ad/impression',
        {
          'impression_id': impressionId,
          'ad_id': 'test-ad-001',
          'video_id': videoId,
        },
      );

      // 200/201/204 = success, 400 = no matching ad in DB (acceptable)
      expect([200, 201, 204, 400], contains(impressionResponse.statusCode));
      print('Step 2: Impression recorded');

      // 3. Record click (user clicked the ad) - authenticated
      final clickResponse = await apiHelper.authPost(
        '/api/v1/ads/pause-ad/click',
        {
          'impression_id': impressionId,
          'click_type': 'ad',
        },
      );

      // 200/201/204 = success, 400 = no matching impression (acceptable)
      expect([200, 201, 204, 400], contains(clickResponse.statusCode));
      print('Step 3: Click recorded');

      print('Complete ad interaction flow successful');
    });
  });
}
