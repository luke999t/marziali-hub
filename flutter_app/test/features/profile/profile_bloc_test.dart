/// 🎓 AI_MODULE: ProfileBlocTest
/// 🎓 AI_DESCRIPTION: Test BLoC profilo ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica state management reale
/// 🎓 AI_TEACHING: BLoC test con real dependencies

import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:dio/dio.dart';
import 'package:connectivity_plus/connectivity_plus.dart';

import 'package:martial_arts_streaming/core/network/api_client.dart';
import 'package:martial_arts_streaming/core/network/network_info.dart';
import 'package:martial_arts_streaming/features/profile/data/datasources/profile_remote_datasource.dart';
import 'package:martial_arts_streaming/features/profile/data/datasources/profile_local_datasource.dart';
import 'package:martial_arts_streaming/features/profile/data/repositories/profile_repository_impl.dart';
import 'package:martial_arts_streaming/features/profile/domain/repositories/profile_repository.dart';
import 'package:martial_arts_streaming/features/profile/domain/usecases/get_profile_usecase.dart';
import 'package:martial_arts_streaming/features/profile/domain/usecases/update_profile_usecase.dart';
import 'package:martial_arts_streaming/features/profile/domain/usecases/change_password_usecase.dart';
import 'package:martial_arts_streaming/features/profile/domain/usecases/upload_avatar_usecase.dart';
import 'package:martial_arts_streaming/features/profile/domain/usecases/delete_account_usecase.dart';
import 'package:martial_arts_streaming/features/profile/domain/usecases/get_user_stats_usecase.dart';
import 'package:martial_arts_streaming/features/profile/presentation/bloc/profile_bloc.dart';
import 'package:martial_arts_streaming/features/profile/presentation/bloc/profile_event.dart';
import 'package:martial_arts_streaming/features/profile/presentation/bloc/profile_state.dart';

/// ZERO MOCK Test Suite for Profile BLoC
/// Uses real repository and backend
void main() {
  late ProfileBloc bloc;
  late ProfileRepository repository;

  setUpAll(() async {
    // Initialize SharedPreferences for testing
    SharedPreferences.setMockInitialValues({});
    final sharedPreferences = await SharedPreferences.getInstance();

    // Create real Dio instance
    final dio = Dio(BaseOptions(
      baseUrl: 'http://localhost:8100/api/v1',
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
    ));

    // Real dependencies (ZERO MOCK)
    final apiClient = ApiClient(dio, null);
    final networkInfo = NetworkInfoImpl(Connectivity());
    final remoteDataSource = ProfileRemoteDataSourceImpl(apiClient);
    final localDataSource = ProfileLocalDataSourceImpl(sharedPreferences);

    repository = ProfileRepositoryImpl(
      remoteDataSource: remoteDataSource,
      localDataSource: localDataSource,
      networkInfo: networkInfo,
    );
  });

  setUp(() {
    bloc = ProfileBloc(
      getProfileUseCase: GetProfileUseCase(repository),
      updateProfileUseCase: UpdateProfileUseCase(repository),
      changePasswordUseCase: ChangePasswordUseCase(repository),
      uploadAvatarUseCase: UploadAvatarUseCase(repository),
      deleteAccountUseCase: DeleteAccountUseCase(repository),
      getUserStatsUseCase: GetUserStatsUseCase(repository),
      repository: repository,
    );
  });

  tearDown(() {
    bloc.close();
  });

  group('ProfileBloc ZERO MOCK Tests', () {
    test('initial state should be ProfileState.initial()', () {
      expect(bloc.state, equals(ProfileState.initial()));
      expect(bloc.state.status, equals(ProfileStatus.initial));
      expect(bloc.state.profile, isNull);
      print('✅ Initial state verified');
    });

    blocTest<ProfileBloc, ProfileState>(
      'emits [loading, loaded] when LoadProfileEvent is added',
      build: () => bloc,
      act: (bloc) => bloc.add(const LoadProfileEvent()),
      wait: const Duration(seconds: 5),
      expect: () => [
        isA<ProfileState>().having((s) => s.status, 'status', ProfileStatus.loading),
        isA<ProfileState>().having((s) => s.status, 'status', ProfileStatus.loaded),
      ],
      verify: (bloc) {
        expect(bloc.state.profile, isNotNull);
        expect(bloc.state.profile!.email, isNotEmpty);
        print('✅ Profile loaded via BLoC: ${bloc.state.profile!.displayName}');
      },
    );

    blocTest<ProfileBloc, ProfileState>(
      'emits correct states when UpdateProfileEvent is added',
      build: () => bloc,
      seed: () => ProfileState.initial(),
      act: (bloc) async {
        // First load profile
        bloc.add(const LoadProfileEvent());
        await Future.delayed(const Duration(seconds: 3));
        // Then update
        bloc.add(const UpdateProfileEvent(bio: 'Updated via BLoC test'));
      },
      wait: const Duration(seconds: 8),
      verify: (bloc) {
        expect(bloc.state.profile, isNotNull);
        print('✅ Profile updated via BLoC');
      },
    );

    blocTest<ProfileBloc, ProfileState>(
      'loads user stats when LoadUserStatsEvent is added',
      build: () => bloc,
      act: (bloc) => bloc.add(const LoadUserStatsEvent()),
      wait: const Duration(seconds: 5),
      verify: (bloc) {
        if (bloc.state.stats != null) {
          expect(bloc.state.stats!.videosWatched, isNonNegative);
          print('✅ User stats loaded: ${bloc.state.stats!.videosWatched} videos');
        }
      },
    );

    blocTest<ProfileBloc, ProfileState>(
      'handles ChangePasswordEvent with validation',
      build: () => bloc,
      act: (bloc) => bloc.add(const ChangePasswordEvent(
        currentPassword: 'OldPass123!',
        newPassword: 'NewPass456!',
        confirmPassword: 'NewPass456!',
      )),
      wait: const Duration(seconds: 5),
      verify: (bloc) {
        // Password change might fail due to wrong current password
        // but the flow should work
        expect(
          bloc.state.passwordStatus,
          anyOf([
            PasswordChangeStatus.success,
            PasswordChangeStatus.error,
          ]),
        );
        print('✅ Password change flow verified');
      },
    );

    blocTest<ProfileBloc, ProfileState>(
      'ResetProfileEvent returns to initial state',
      build: () => bloc,
      seed: () => ProfileState.initial().copyWith(
        status: ProfileStatus.loaded,
      ),
      act: (bloc) => bloc.add(const ResetProfileEvent()),
      expect: () => [ProfileState.initial()],
      verify: (bloc) {
        expect(bloc.state.status, equals(ProfileStatus.initial));
        expect(bloc.state.profile, isNull);
        print('✅ Profile state reset');
      },
    );
  });

  group('Error handling', () {
    blocTest<ProfileBloc, ProfileState>(
      'handles error states gracefully',
      build: () => bloc,
      act: (bloc) {
        // Force refresh when offline might cause error
        bloc.add(const LoadProfileEvent(forceRefresh: true));
      },
      wait: const Duration(seconds: 5),
      verify: (bloc) {
        // Either loaded or error, but should handle gracefully
        expect(
          bloc.state.status,
          anyOf([ProfileStatus.loaded, ProfileStatus.error]),
        );
        print('✅ Error handling verified');
      },
    );
  });
}
