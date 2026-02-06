/// 🎓 AI_MODULE: OfflineStorageTest
/// 🎓 AI_DESCRIPTION: Test storage Hive ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica persistenza offline
/// 🎓 AI_TEACHING: Hive integration test

import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';

import 'package:martial_arts_streaming/core/offline/offline_storage.dart';

/// ZERO MOCK Test Suite for Offline Storage
/// Tests real Hive operations
void main() {
  late HiveOfflineStorage storage;

  setUpAll(() async {
    // Initialize Hive for testing
    await Hive.initFlutter('test_hive');
    storage = HiveOfflineStorage();
    await storage.init();
  });

  tearDownAll(() async {
    await storage.clearAll();
    await storage.close();
  });

  group('HiveOfflineStorage ZERO MOCK Tests', () {
    group('basic operations', () {
      test('should store and retrieve string value', () async {
        // Arrange
        const boxName = OfflineBoxes.cache;
        const key = 'test_string';
        const value = 'Hello, Hive!';

        // Act
        await storage.put(boxName, key, value);
        final result = await storage.get<String>(boxName, key);

        // Assert
        expect(result, equals(value));
        print('✅ String stored and retrieved: $result');
      });

      test('should store and retrieve map value', () async {
        // Arrange
        const boxName = OfflineBoxes.cache;
        const key = 'test_map';
        final value = {'name': 'Test', 'age': 25, 'active': true};

        // Act
        await storage.put(boxName, key, value);
        final result = await storage.get(boxName, key);

        // Assert
        expect(result, isA<Map>());
        expect(result['name'], equals('Test'));
        expect(result['age'], equals(25));
        print('✅ Map stored and retrieved: $result');
      });

      test('should store and retrieve list value', () async {
        // Arrange
        const boxName = OfflineBoxes.cache;
        const key = 'test_list';
        final value = [1, 2, 3, 'four', true];

        // Act
        await storage.put(boxName, key, value);
        final result = await storage.get(boxName, key);

        // Assert
        expect(result, isA<List>());
        expect(result.length, equals(5));
        print('✅ List stored and retrieved: $result');
      });

      test('should return null for non-existent key', () async {
        // Act
        final result = await storage.get<String>(OfflineBoxes.cache, 'non_existent');

        // Assert
        expect(result, isNull);
        print('✅ Non-existent key returns null');
      });
    });

    group('box operations', () {
      test('should check if key exists', () async {
        // Arrange
        const boxName = OfflineBoxes.cache;
        const key = 'exists_test';
        await storage.put(boxName, key, 'value');

        // Act
        final exists = await storage.containsKey(boxName, key);
        final notExists = await storage.containsKey(boxName, 'not_exists');

        // Assert
        expect(exists, isTrue);
        expect(notExists, isFalse);
        print('✅ containsKey works correctly');
      });

      test('should delete specific key', () async {
        // Arrange
        const boxName = OfflineBoxes.cache;
        const key = 'delete_test';
        await storage.put(boxName, key, 'to_delete');

        // Act
        await storage.delete(boxName, key);
        final result = await storage.get(boxName, key);

        // Assert
        expect(result, isNull);
        print('✅ Key deleted successfully');
      });

      test('should get all values from box', () async {
        // Arrange
        const boxName = OfflineBoxes.metadata;
        await storage.clearBox(boxName);
        await storage.put(boxName, 'key1', {'value': 1});
        await storage.put(boxName, 'key2', {'value': 2});

        // Act
        final all = await storage.getAll(boxName);

        // Assert
        expect(all.length, equals(2));
        expect(all['key1'], isNotNull);
        expect(all['key2'], isNotNull);
        print('✅ getAll returns ${all.length} items');
      });

      test('should get box size', () async {
        // Arrange
        const boxName = OfflineBoxes.metadata;

        // Act
        final size = await storage.getBoxSize(boxName);

        // Assert
        expect(size, isNonNegative);
        print('✅ Box size: $size items');
      });

      test('should clear specific box', () async {
        // Arrange
        const boxName = OfflineBoxes.metadata;
        await storage.put(boxName, 'clear_test', 'value');

        // Act
        await storage.clearBox(boxName);
        final size = await storage.getBoxSize(boxName);

        // Assert
        expect(size, equals(0));
        print('✅ Box cleared successfully');
      });
    });

    group('TTL operations', () {
      test('should store with TTL and retrieve before expiry', () async {
        // Arrange
        const boxName = OfflineBoxes.cache;
        const key = 'ttl_test';
        final data = {'cached': true};
        const ttl = Duration(hours: 1);

        // Act
        await storage.putWithTTL(boxName, key, data, ttl);
        final result = await storage.getWithTTL<Map>(boxName, key);

        // Assert
        expect(result, isNotNull);
        expect(result!['cached'], isTrue);
        print('✅ TTL cache works correctly');
      });

      test('should return null for expired TTL cache', () async {
        // Arrange
        const boxName = OfflineBoxes.cache;
        const key = 'expired_ttl_test';
        final data = {'expired': true};
        const ttl = Duration(milliseconds: 1); // Expires immediately

        // Act
        await storage.putWithTTL(boxName, key, data, ttl);
        await Future.delayed(const Duration(milliseconds: 10));
        final result = await storage.getWithTTL<Map>(boxName, key);

        // Assert
        expect(result, isNull);
        print('✅ Expired TTL cache returns null');
      });
    });

    group('profile storage', () {
      test('should store and retrieve profile data', () async {
        // Arrange
        const boxName = OfflineBoxes.profile;
        const key = 'current_profile';
        final profileData = {
          'id': 'user123',
          'email': 'test@example.com',
          'name': 'Test User',
          'tier': 'premium',
        };

        // Act
        await storage.put(boxName, key, profileData);
        final result = await storage.get(boxName, key);

        // Assert
        expect(result, isNotNull);
        expect(result['id'], equals('user123'));
        expect(result['email'], equals('test@example.com'));
        print('✅ Profile data stored: ${result['email']}');
      });
    });

    group('settings storage', () {
      test('should store and retrieve settings data', () async {
        // Arrange
        const boxName = OfflineBoxes.settings;
        const key = 'current_settings';
        final settingsData = {
          'theme': 'dark',
          'language': 'it',
          'notifications': true,
        };

        // Act
        await storage.put(boxName, key, settingsData);
        final result = await storage.get(boxName, key);

        // Assert
        expect(result, isNotNull);
        expect(result['theme'], equals('dark'));
        print('✅ Settings data stored: theme=${result['theme']}');
      });
    });
  });
}
