import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:martial_arts_streaming/features/auth/data/datasources/auth_local_datasource.dart';
import 'package:martial_arts_streaming/features/auth/data/models/user_model.dart';
import 'package:martial_arts_streaming/features/auth/domain/entities/user.dart';

import '../../../../../test_config.dart';
import '../../../../../mocks/mock_repositories.dart';

class MockSharedPreferences extends Mock implements SharedPreferences {}

@Tags([TestTags.unit])
void main() {
  late AuthLocalDataSourceImpl dataSource;
  late MockFlutterSecureStorage mockSecureStorage;
  late MockSharedPreferences mockSharedPrefs;

  setUpAll(() {
    registerFallbackValues();
  });

  setUp(() {
    mockSecureStorage = MockFlutterSecureStorage();
    mockSharedPrefs = MockSharedPreferences();
    dataSource = AuthLocalDataSourceImpl(mockSecureStorage, mockSharedPrefs);
  });

  group('AuthLocalDataSource', () {
    group('cacheTokens', () {
      test('should store access and refresh tokens in secure storage', () async {
        // Arrange
        const accessToken = 'test_access_token';
        const refreshToken = 'test_refresh_token';

        when(() => mockSecureStorage.write(
              key: any(named: 'key'),
              value: any(named: 'value'),
            )).thenAnswer((_) async {});

        // Act
        await dataSource.cacheTokens(
          accessToken: accessToken,
          refreshToken: refreshToken,
        );

        // Assert
        verify(() => mockSecureStorage.write(
              key: 'access_token',
              value: accessToken,
            )).called(1);
        verify(() => mockSecureStorage.write(
              key: 'refresh_token',
              value: refreshToken,
            )).called(1);
      });
    });

    group('getAccessToken', () {
      test('should return access token when it exists', () async {
        // Arrange
        const expectedToken = 'stored_access_token';
        when(() => mockSecureStorage.read(key: 'access_token'))
            .thenAnswer((_) async => expectedToken);

        // Act
        final result = await dataSource.getAccessToken();

        // Assert
        expect(result, equals(expectedToken));
      });

      test('should return null when access token does not exist', () async {
        // Arrange
        when(() => mockSecureStorage.read(key: 'access_token'))
            .thenAnswer((_) async => null);

        // Act
        final result = await dataSource.getAccessToken();

        // Assert
        expect(result, isNull);
      });
    });

    group('getRefreshToken', () {
      test('should return refresh token when it exists', () async {
        // Arrange
        const expectedToken = 'stored_refresh_token';
        when(() => mockSecureStorage.read(key: 'refresh_token'))
            .thenAnswer((_) async => expectedToken);

        // Act
        final result = await dataSource.getRefreshToken();

        // Assert
        expect(result, equals(expectedToken));
      });

      test('should return null when refresh token does not exist', () async {
        // Arrange
        when(() => mockSecureStorage.read(key: 'refresh_token'))
            .thenAnswer((_) async => null);

        // Act
        final result = await dataSource.getRefreshToken();

        // Assert
        expect(result, isNull);
      });
    });

    group('clearTokens', () {
      test('should delete both tokens from secure storage', () async {
        // Arrange
        when(() => mockSecureStorage.delete(key: any(named: 'key')))
            .thenAnswer((_) async {});

        // Act
        await dataSource.clearTokens();

        // Assert
        verify(() => mockSecureStorage.delete(key: 'access_token')).called(1);
        verify(() => mockSecureStorage.delete(key: 'refresh_token')).called(1);
      });
    });

    group('cacheProfileId', () {
      test('should store profile ID in secure storage', () async {
        // Arrange
        const profileId = 'profile_123';
        when(() => mockSecureStorage.write(
              key: any(named: 'key'),
              value: any(named: 'value'),
            )).thenAnswer((_) async {});

        // Act
        await dataSource.cacheProfileId(profileId);

        // Assert
        verify(() => mockSecureStorage.write(
              key: 'selected_profile_id',
              value: profileId,
            )).called(1);
      });
    });

    group('getSelectedProfileId', () {
      test('should return profile ID when it exists', () async {
        // Arrange
        const expectedId = 'stored_profile_id';
        when(() => mockSecureStorage.read(key: 'selected_profile_id'))
            .thenAnswer((_) async => expectedId);

        // Act
        final result = await dataSource.getSelectedProfileId();

        // Assert
        expect(result, equals(expectedId));
      });

      test('should return null when profile ID does not exist', () async {
        // Arrange
        when(() => mockSecureStorage.read(key: 'selected_profile_id'))
            .thenAnswer((_) async => null);

        // Act
        final result = await dataSource.getSelectedProfileId();

        // Assert
        expect(result, isNull);
      });
    });
  });

  group('UserModel serialization', () {
    test('should correctly serialize and deserialize user', () {
      // Arrange
      final user = UserModel(
        id: 'user_123',
        email: 'test@example.com',
        username: 'testuser',
        tier: UserTier.premium,
        isVerified: true,
        isMaestro: false,
        createdAt: DateTime(2024, 1, 1),
        preferences: const UserPreferencesModel(),
        stellineBalance: 100,
      );

      // Act
      final json = user.toJson();
      final restored = UserModel.fromJson(json);

      // Assert
      expect(restored.id, equals(user.id));
      expect(restored.email, equals(user.email));
      expect(restored.username, equals(user.username));
      expect(restored.tier, equals(user.tier));
      expect(restored.isVerified, equals(user.isVerified));
    });

    test('should handle null avatar and use defaults', () {
      // Arrange
      final json = {
        'id': 'user_123',
        'email': 'test@example.com',
        'username': 'testuser',
        'tier': null,
        'is_verified': false,
      };

      // Act
      final user = UserModel.fromJson(json);

      // Assert
      expect(user.avatarUrl, isNull);
      expect(user.tier, equals(UserTier.free));
    });

    test('should correctly parse all user tiers', () {
      final testCases = {
        'free': UserTier.free,
        'hybrid_light': UserTier.hybridLight,
        'hybrid_standard': UserTier.hybridStandard,
        'premium': UserTier.premium,
        'business': UserTier.business,
      };

      for (final entry in testCases.entries) {
        final json = {
          'id': 'user_123',
          'email': 'test@example.com',
          'username': 'testuser',
          'tier': entry.key,
        };

        final user = UserModel.fromJson(json);
        expect(user.tier, equals(entry.value), reason: 'Failed for tier: ${entry.key}');
      }
    });
  });

  group('UserProfileModel serialization', () {
    test('should correctly serialize and deserialize profile', () {
      // Arrange
      const profile = UserProfileModel(
        id: 'profile_123',
        name: 'Main Profile',
        avatarUrl: 'https://example.com/avatar.jpg',
        isKids: false,
        isDefault: true,
        favoriteCategories: ['martial_arts', 'fitness'],
      );

      // Act
      final json = profile.toJson();
      final restored = UserProfileModel.fromJson(json);

      // Assert
      expect(restored.id, equals(profile.id));
      expect(restored.name, equals(profile.name));
      expect(restored.avatarUrl, equals(profile.avatarUrl));
      expect(restored.isKids, equals(profile.isKids));
      expect(restored.isDefault, equals(profile.isDefault));
    });

    test('should handle kids profile with appropriate defaults', () {
      // Arrange
      final json = {
        'id': 'profile_kids',
        'name': 'Kids Profile',
        'is_kids': true,
        'is_default': false,
      };

      // Act
      final profile = UserProfileModel.fromJson(json);

      // Assert
      expect(profile.isKids, isTrue);
      expect(profile.isDefault, isFalse);
    });
  });
}
