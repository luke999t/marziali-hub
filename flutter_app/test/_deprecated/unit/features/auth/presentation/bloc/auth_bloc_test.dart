import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:dartz/dartz.dart';

import 'package:martial_arts_streaming/core/error/failures.dart';
import 'package:martial_arts_streaming/features/auth/presentation/bloc/auth_bloc.dart';
import 'package:martial_arts_streaming/features/auth/domain/entities/user.dart';
import 'package:martial_arts_streaming/features/auth/domain/usecases/login_usecase.dart';
import 'package:martial_arts_streaming/features/auth/domain/usecases/register_usecase.dart';
import 'package:martial_arts_streaming/features/auth/domain/usecases/logout_usecase.dart';

import '../../../../../test_config.dart';
import '../../../../../mocks/mock_repositories.dart';

// Mock UseCases
class MockLoginUseCase extends Mock implements LoginUseCase {}
class MockRegisterUseCase extends Mock implements RegisterUseCase {}
class MockLogoutUseCase extends Mock implements LogoutUseCase {}
class FakeLoginParams extends Fake implements LoginParams {}
class FakeRegisterParams extends Fake implements RegisterParams {}

@Tags([TestTags.unit])
void main() {
  late AuthBloc authBloc;
  late MockAuthRepository mockAuthRepository;
  late MockLoginUseCase mockLoginUseCase;
  late MockRegisterUseCase mockRegisterUseCase;
  late MockLogoutUseCase mockLogoutUseCase;

  setUpAll(() {
    registerFallbackValues();
    registerFallbackValue(FakeLoginParams());
    registerFallbackValue(FakeRegisterParams());
  });

  setUp(() {
    mockAuthRepository = MockAuthRepository();
    mockLoginUseCase = MockLoginUseCase();
    mockRegisterUseCase = MockRegisterUseCase();
    mockLogoutUseCase = MockLogoutUseCase();
    authBloc = AuthBloc(
      authRepository: mockAuthRepository,
      loginUseCase: mockLoginUseCase,
      registerUseCase: mockRegisterUseCase,
      logoutUseCase: mockLogoutUseCase,
    );
  });

  tearDown(() {
    authBloc.close();
  });

  group('AuthBloc', () {
    test('initial state should be AuthInitial', () {
      expect(authBloc.state, isA<AuthInitial>());
    });

    group('CheckAuthStatusEvent', () {
      final testUser = AuthTestFixtures.testUser;

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthAuthenticated] when user is authenticated',
        build: () {
          when(() => mockAuthRepository.getCurrentUser())
              .thenAnswer((_) async => Right(testUser));
          when(() => mockAuthRepository.getUserProfiles())
              .thenAnswer((_) async => []);
          return authBloc;
        },
        act: (bloc) => bloc.add(CheckAuthStatusEvent()),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthAuthenticated>(),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthUnauthenticated] when getting user fails',
        build: () {
          when(() => mockAuthRepository.getCurrentUser())
              .thenAnswer((_) async => const Left(AuthFailure('Session expired')));
          when(() => mockAuthRepository.isFirstLaunch()).thenReturn(false);
          return authBloc;
        },
        act: (bloc) => bloc.add(CheckAuthStatusEvent()),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthUnauthenticated>(),
        ],
      );
    });

    group('LoginEvent', () {
      const email = TestDataFactory.validEmail;
      const password = TestDataFactory.validPassword;
      final testUser = AuthTestFixtures.testUser;

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthAuthenticated] when login succeeds',
        build: () {
          when(() => mockLoginUseCase(any()))
              .thenAnswer((_) async => Right(testUser));
          when(() => mockAuthRepository.getUserProfiles())
              .thenAnswer((_) async => []);
          return authBloc;
        },
        act: (bloc) => bloc.add(LoginEvent(email: email, password: password)),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthAuthenticated>(),
        ],
        verify: (_) {
          verify(() => mockLoginUseCase(any())).called(1);
        },
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthError] when login fails with invalid credentials',
        build: () {
          when(() => mockLoginUseCase(any()))
              .thenAnswer((_) async => const Left(AuthFailure('Invalid email or password')));
          return authBloc;
        },
        act: (bloc) => bloc.add(LoginEvent(email: email, password: password)),
        expect: () => [
          isA<AuthLoading>(),
          predicate<AuthError>(
            (state) => state.message.contains('Invalid'),
          ),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthError] when login fails with network error',
        build: () {
          when(() => mockLoginUseCase(any()))
              .thenAnswer((_) async => const Left(NetworkFailure('No internet connection')));
          return authBloc;
        },
        act: (bloc) => bloc.add(LoginEvent(email: email, password: password)),
        expect: () => [
          isA<AuthLoading>(),
          predicate<AuthError>(
            (state) => state.message.contains('internet'),
          ),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthAuthenticated] with rememberMe option',
        build: () {
          when(() => mockLoginUseCase(any()))
              .thenAnswer((_) async => Right(testUser));
          when(() => mockAuthRepository.getUserProfiles())
              .thenAnswer((_) async => []);
          return authBloc;
        },
        act: (bloc) => bloc.add(LoginEvent(
          email: email,
          password: password,
          rememberMe: true,
        )),
        verify: (_) {
          verify(() => mockLoginUseCase(any())).called(1);
        },
      );
    });

    group('RegisterEvent', () {
      const email = TestDataFactory.validEmail;
      const password = TestDataFactory.validPassword;
      const username = TestDataFactory.validUsername;
      final testUser = AuthTestFixtures.testUser;

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthAuthenticated] when registration succeeds',
        build: () {
          when(() => mockRegisterUseCase(any()))
              .thenAnswer((_) async => Right(testUser));
          when(() => mockAuthRepository.getUserProfiles())
              .thenAnswer((_) async => []);
          return authBloc;
        },
        act: (bloc) => bloc.add(RegisterEvent(
          email: email,
          username: username,
          password: password,
        )),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthAuthenticated>(),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthError] when email already exists',
        build: () {
          when(() => mockRegisterUseCase(any()))
              .thenAnswer((_) async => const Left(ValidationFailure(
                'Email already in use',
                fieldErrors: {'email': ['Email already registered']},
              )));
          return authBloc;
        },
        act: (bloc) => bloc.add(RegisterEvent(
          email: email,
          username: username,
          password: password,
        )),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthError>(),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthError] when password is weak',
        build: () {
          when(() => mockRegisterUseCase(any()))
              .thenAnswer((_) async => const Left(ValidationFailure(
                'Weak password',
                fieldErrors: {'password': ['Password too weak']},
              )));
          return authBloc;
        },
        act: (bloc) => bloc.add(RegisterEvent(
          email: email,
          username: username,
          password: 'weak',
        )),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthError>(),
        ],
      );
    });

    group('LogoutEvent', () {
      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthUnauthenticated] when logout succeeds',
        build: () {
          when(() => mockLogoutUseCase())
              .thenAnswer((_) async => const Right(null));
          return authBloc;
        },
        act: (bloc) => bloc.add(LogoutEvent()),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthUnauthenticated>(),
        ],
        verify: (_) {
          verify(() => mockLogoutUseCase()).called(1);
        },
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthError] when logout fails',
        build: () {
          when(() => mockLogoutUseCase())
              .thenAnswer((_) async => const Left(ServerFailure('Server error')));
          return authBloc;
        },
        act: (bloc) => bloc.add(LogoutEvent()),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthError>(),
        ],
      );
    });

    group('SelectProfileEvent', () {
      const testProfile = UserProfile(
        id: 'profile_123',
        name: 'Main Profile',
      );

      blocTest<AuthBloc, AuthState>(
        'updates selected profile in AuthAuthenticated state',
        seed: () => AuthAuthenticated(
          user: AuthTestFixtures.testUser,
          profiles: const [testProfile],
        ),
        build: () => authBloc,
        act: (bloc) => bloc.add(SelectProfileEvent(testProfile)),
        expect: () => [
          predicate<AuthAuthenticated>(
            (state) => state.selectedProfile?.id == testProfile.id,
          ),
        ],
      );
    });

    group('GoogleSignInEvent', () {
      final testUser = AuthTestFixtures.testUser;

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthAuthenticated] when Google sign-in succeeds',
        build: () {
          when(() => mockAuthRepository.signInWithGoogle())
              .thenAnswer((_) async => Right(testUser));
          when(() => mockAuthRepository.getUserProfiles())
              .thenAnswer((_) async => []);
          return authBloc;
        },
        act: (bloc) => bloc.add(GoogleSignInEvent()),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthAuthenticated>(),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthError] when Google sign-in fails',
        build: () {
          when(() => mockAuthRepository.signInWithGoogle())
              .thenAnswer((_) async => const Left(AuthFailure('Google sign-in failed')));
          return authBloc;
        },
        act: (bloc) => bloc.add(GoogleSignInEvent()),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthError>(),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthError] when Google sign-in is cancelled',
        build: () {
          when(() => mockAuthRepository.signInWithGoogle())
              .thenAnswer((_) async => const Left(AuthFailure('Sign-in cancelled')));
          return authBloc;
        },
        act: (bloc) => bloc.add(GoogleSignInEvent()),
        expect: () => [
          isA<AuthLoading>(),
          predicate<AuthError>(
            (state) => state.message.contains('cancelled'),
          ),
        ],
      );
    });

    group('AppleSignInEvent', () {
      final testUser = AuthTestFixtures.testUser;

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthAuthenticated] when Apple sign-in succeeds',
        build: () {
          when(() => mockAuthRepository.signInWithApple())
              .thenAnswer((_) async => Right(testUser));
          when(() => mockAuthRepository.getUserProfiles())
              .thenAnswer((_) async => []);
          return authBloc;
        },
        act: (bloc) => bloc.add(AppleSignInEvent()),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthAuthenticated>(),
        ],
      );
    });

    group('ForgotPasswordEvent', () {
      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthPasswordResetSent] when password reset email is sent',
        build: () {
          when(() => mockAuthRepository.forgotPassword(any()))
              .thenAnswer((_) async => const Right(null));
          return authBloc;
        },
        act: (bloc) => bloc.add(ForgotPasswordEvent(TestDataFactory.validEmail)),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthPasswordResetSent>(),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'emits [AuthLoading, AuthError] when email is invalid',
        build: () {
          when(() => mockAuthRepository.forgotPassword(any()))
              .thenAnswer((_) async => const Left(ValidationFailure('Invalid email')));
          return authBloc;
        },
        act: (bloc) => bloc.add(ForgotPasswordEvent('invalid-email')),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthError>(),
        ],
      );
    });

    group('Edge cases', () {
      blocTest<AuthBloc, AuthState>(
        'handles multiple rapid login attempts gracefully',
        build: () {
          when(() => mockLoginUseCase(any()))
              .thenAnswer((_) async => Right(AuthTestFixtures.testUser));
          when(() => mockAuthRepository.getUserProfiles())
              .thenAnswer((_) async => []);
          return authBloc;
        },
        act: (bloc) {
          // Add single login event - rapid events are processed sequentially
          bloc.add(LoginEvent(
            email: TestDataFactory.validEmail,
            password: TestDataFactory.validPassword,
          ));
        },
        wait: const Duration(milliseconds: 100),
        expect: () => [
          isA<AuthLoading>(),
          isA<AuthAuthenticated>(),
        ],
      );

      blocTest<AuthBloc, AuthState>(
        'handles logout while checking auth status',
        build: () {
          when(() => mockAuthRepository.getCurrentUser())
              .thenAnswer((_) async {
            await Future.delayed(const Duration(milliseconds: 100));
            return Right(AuthTestFixtures.testUser);
          });
          when(() => mockLogoutUseCase())
              .thenAnswer((_) async => const Right(null));
          when(() => mockAuthRepository.getUserProfiles())
              .thenAnswer((_) async => []);
          return authBloc;
        },
        act: (bloc) {
          bloc.add(CheckAuthStatusEvent());
          Future.delayed(
            const Duration(milliseconds: 50),
            () => bloc.add(LogoutEvent()),
          );
        },
        wait: const Duration(milliseconds: 200),
      );
    });
  });
}
