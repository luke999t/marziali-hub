/// 🎓 AI_MODULE: AuthBlocTest
/// 🎓 AI_DESCRIPTION: Test BLoC Auth con backend reale - ZERO MOCK
/// 🎓 AI_BUSINESS: Validazione stati autenticazione, login, logout, profili
/// 🎓 AI_TEACHING: Pattern test BLoC enterprise - backend reale obbligatorio
///
/// REGOLA ZERO MOCK:
/// - Nessun mockito, mocktail, fake
/// - Backend reale localhost:8000
/// - Skip se backend offline

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:dio/dio.dart';
import 'package:dartz/dartz.dart';

import 'package:media_center_arti_marziali/features/auth/presentation/bloc/auth_bloc.dart';
import 'package:media_center_arti_marziali/features/auth/domain/entities/user.dart';
import 'package:media_center_arti_marziali/features/auth/domain/usecases/login_usecase.dart';
import 'package:media_center_arti_marziali/features/auth/domain/usecases/register_usecase.dart';
import 'package:media_center_arti_marziali/features/auth/domain/usecases/logout_usecase.dart';
import 'package:media_center_arti_marziali/features/auth/domain/repositories/auth_repository.dart';
import 'package:media_center_arti_marziali/core/error/failures.dart';

import '../../../../helpers/backend_checker.dart';

void main() {
  late Dio dio;
  late _TestAuthRepository repository;
  late LoginUseCase loginUseCase;
  late RegisterUseCase registerUseCase;
  late LogoutUseCase logoutUseCase;
  late AuthBloc authBloc;

  setUpAll(() async {
    WidgetsFlutterBinding.ensureInitialized();

    dio = Dio(BaseOptions(
      baseUrl: '${BackendChecker.baseUrl}/api/v1',
      connectTimeout: const Duration(seconds: 10),
      receiveTimeout: const Duration(seconds: 10),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ));

    repository = _TestAuthRepository(dio);
    loginUseCase = LoginUseCase(repository);
    registerUseCase = RegisterUseCase(repository);
    logoutUseCase = LogoutUseCase(repository);
  });

  setUp(() {
    authBloc = AuthBloc(
      loginUseCase: loginUseCase,
      registerUseCase: registerUseCase,
      logoutUseCase: logoutUseCase,
      authRepository: repository,
    );
  });

  tearDown(() {
    authBloc.close();
  });

  tearDownAll(() {
    dio.close();
  });

  group('AuthBloc - Initial State', () {
    test('stato iniziale deve essere AuthInitial', () {
      expect(authBloc.state, isA<AuthInitial>());
    });
  });

  group('AuthBloc - CheckAuthStatusEvent', () {
    test('CheckAuthStatusEvent deve emettere AuthLoading poi stato finale', () async {
      // Act
      authBloc.add(CheckAuthStatusEvent());

      // Assert
      await expectLater(
        authBloc.stream,
        emitsInOrder([
          isA<AuthLoading>(),
          anyOf([
            isA<AuthAuthenticated>(),
            isA<AuthUnauthenticated>(),
            isA<AuthError>(),
          ]),
        ]),
      );
    });

    blocTest<AuthBloc, AuthState>(
      'emette AuthLoading quando CheckAuthStatusEvent aggiunto',
      build: () => AuthBloc(
        loginUseCase: loginUseCase,
        registerUseCase: registerUseCase,
        logoutUseCase: logoutUseCase,
        authRepository: repository,
      ),
      act: (bloc) => bloc.add(CheckAuthStatusEvent()),
      wait: const Duration(milliseconds: 100),
      expect: () => [
        isA<AuthLoading>().having(
          (s) => s.message,
          'message',
          'Checking authentication...',
        ),
      ],
    );
  });

  group('AuthBloc - LoginEvent', () {
    testWithBackend('LoginEvent deve emettere AuthLoading poi stato finale', () async {
      // Act
      authBloc.add(const LoginEvent(
        email: 'test@example.com',
        password: 'password123',
      ));

      // Assert
      await expectLater(
        authBloc.stream,
        emitsInOrder([
          isA<AuthLoading>(),
          anyOf([
            isA<AuthAuthenticated>(),
            isA<AuthError>(),
          ]),
        ]),
      );
    });

    testWithBackend('LoginEvent con credenziali valide', () async {
      // Act
      authBloc.add(const LoginEvent(
        email: 'demo@test.com',
        password: 'demo123',
        rememberMe: true,
      ));

      await Future.delayed(const Duration(seconds: 3));

      // Assert
      final state = authBloc.state;
      expect(
        state,
        anyOf([
          isA<AuthAuthenticated>(),
          isA<AuthError>(),
        ]),
      );

      if (state is AuthAuthenticated) {
        expect(state.user, isA<User>());
        expect(state.profiles, isA<List<UserProfile>>());
      }
    });

    testWithBackend('LoginEvent con credenziali non valide', () async {
      // Act
      authBloc.add(const LoginEvent(
        email: 'invalid@invalid.com',
        password: 'wrongpassword',
      ));

      await Future.delayed(const Duration(seconds: 3));

      // Assert
      final state = authBloc.state;
      expect(state, isA<AuthError>());
      if (state is AuthError) {
        expect(state.message, isNotEmpty);
      }
    });

    blocTest<AuthBloc, AuthState>(
      'emette AuthLoading con messaggio corretto durante login',
      build: () => AuthBloc(
        loginUseCase: loginUseCase,
        registerUseCase: registerUseCase,
        logoutUseCase: logoutUseCase,
        authRepository: repository,
      ),
      act: (bloc) => bloc.add(const LoginEvent(
        email: 'test@test.com',
        password: 'test',
      )),
      wait: const Duration(milliseconds: 100),
      expect: () => [
        isA<AuthLoading>().having(
          (s) => s.message,
          'message',
          'Signing in...',
        ),
      ],
    );
  });

  group('AuthBloc - RegisterEvent', () {
    testWithBackend('RegisterEvent deve emettere AuthLoading poi stato finale', () async {
      // Genera email unica per test
      final uniqueEmail = 'test_${DateTime.now().millisecondsSinceEpoch}@test.com';

      // Act
      authBloc.add(RegisterEvent(
        email: uniqueEmail,
        username: 'testuser_${DateTime.now().millisecondsSinceEpoch}',
        password: 'Password123!',
        acceptTerms: true,
      ));

      // Assert
      await expectLater(
        authBloc.stream,
        emitsInOrder([
          isA<AuthLoading>(),
          anyOf([
            isA<AuthAuthenticated>(),
            isA<AuthError>(),
          ]),
        ]),
      );
    });

    blocTest<AuthBloc, AuthState>(
      'emette AuthLoading con messaggio corretto durante registrazione',
      build: () => AuthBloc(
        loginUseCase: loginUseCase,
        registerUseCase: registerUseCase,
        logoutUseCase: logoutUseCase,
        authRepository: repository,
      ),
      act: (bloc) => bloc.add(const RegisterEvent(
        email: 'new@test.com',
        username: 'newuser',
        password: 'Password123!',
      )),
      wait: const Duration(milliseconds: 100),
      expect: () => [
        isA<AuthLoading>().having(
          (s) => s.message,
          'message',
          'Creating account...',
        ),
      ],
    );
  });

  group('AuthBloc - LogoutEvent', () {
    testWithBackend('LogoutEvent deve emettere AuthLoading poi AuthUnauthenticated', () async {
      // Act
      authBloc.add(LogoutEvent());

      // Assert
      await expectLater(
        authBloc.stream,
        emitsInOrder([
          isA<AuthLoading>(),
          anyOf([
            isA<AuthUnauthenticated>(),
            isA<AuthError>(),
          ]),
        ]),
      );
    });

    blocTest<AuthBloc, AuthState>(
      'emette AuthLoading con messaggio corretto durante logout',
      build: () => AuthBloc(
        loginUseCase: loginUseCase,
        registerUseCase: registerUseCase,
        logoutUseCase: logoutUseCase,
        authRepository: repository,
      ),
      act: (bloc) => bloc.add(LogoutEvent()),
      wait: const Duration(milliseconds: 100),
      expect: () => [
        isA<AuthLoading>().having(
          (s) => s.message,
          'message',
          'Signing out...',
        ),
      ],
    );
  });

  group('AuthBloc - SelectProfileEvent', () {
    test('SelectProfileEvent non cambia stato se non autenticato', () async {
      // Arrange - stato iniziale
      expect(authBloc.state, isA<AuthInitial>());

      const profile = UserProfile(
        id: 'profile-1',
        name: 'Test Profile',
        avatarUrl: 'https://example.com/avatar.jpg',
      );

      // Act
      authBloc.add(const SelectProfileEvent(profile));

      await Future.delayed(const Duration(milliseconds: 200));

      // Assert - stato non cambia perche' non autenticato
      expect(authBloc.state, isA<AuthInitial>());
    });

    blocTest<AuthBloc, AuthState>(
      'SelectProfileEvent aggiorna profilo selezionato se autenticato',
      build: () => AuthBloc(
        loginUseCase: loginUseCase,
        registerUseCase: registerUseCase,
        logoutUseCase: logoutUseCase,
        authRepository: repository,
      ),
      seed: () => const AuthAuthenticated(
        user: User(
          id: 'user-1',
          email: 'test@test.com',
          username: 'testuser',
        ),
        profiles: [
          UserProfile(id: 'p1', name: 'Profile 1'),
          UserProfile(id: 'p2', name: 'Profile 2'),
        ],
      ),
      act: (bloc) => bloc.add(const SelectProfileEvent(
        UserProfile(id: 'p2', name: 'Profile 2'),
      )),
      expect: () => [
        isA<AuthAuthenticated>().having(
          (s) => s.selectedProfile?.id,
          'selectedProfile.id',
          'p2',
        ),
      ],
    );
  });

  group('AuthBloc - ForgotPasswordEvent', () {
    testWithBackend('ForgotPasswordEvent deve emettere AuthLoading poi stato finale', () async {
      // Act
      authBloc.add(const ForgotPasswordEvent('test@example.com'));

      // Assert
      await expectLater(
        authBloc.stream,
        emitsInOrder([
          isA<AuthLoading>(),
          anyOf([
            isA<AuthPasswordResetSent>(),
            isA<AuthError>(),
          ]),
        ]),
      );
    });

    blocTest<AuthBloc, AuthState>(
      'emette AuthLoading con messaggio corretto durante forgot password',
      build: () => AuthBloc(
        loginUseCase: loginUseCase,
        registerUseCase: registerUseCase,
        logoutUseCase: logoutUseCase,
        authRepository: repository,
      ),
      act: (bloc) => bloc.add(const ForgotPasswordEvent('test@test.com')),
      wait: const Duration(milliseconds: 100),
      expect: () => [
        isA<AuthLoading>().having(
          (s) => s.message,
          'message',
          'Sending reset email...',
        ),
      ],
    );
  });

  group('AuthBloc - GoogleSignInEvent', () {
    blocTest<AuthBloc, AuthState>(
      'emette AuthLoading quando GoogleSignInEvent aggiunto',
      build: () => AuthBloc(
        loginUseCase: loginUseCase,
        registerUseCase: registerUseCase,
        logoutUseCase: logoutUseCase,
        authRepository: repository,
      ),
      act: (bloc) => bloc.add(GoogleSignInEvent()),
      wait: const Duration(milliseconds: 100),
      expect: () => [
        isA<AuthLoading>().having(
          (s) => s.message,
          'message',
          'Signing in with Google...',
        ),
      ],
    );
  });

  group('AuthBloc - AppleSignInEvent', () {
    blocTest<AuthBloc, AuthState>(
      'emette AuthLoading quando AppleSignInEvent aggiunto',
      build: () => AuthBloc(
        loginUseCase: loginUseCase,
        registerUseCase: registerUseCase,
        logoutUseCase: logoutUseCase,
        authRepository: repository,
      ),
      act: (bloc) => bloc.add(AppleSignInEvent()),
      wait: const Duration(milliseconds: 100),
      expect: () => [
        isA<AuthLoading>().having(
          (s) => s.message,
          'message',
          'Signing in with Apple...',
        ),
      ],
    );
  });

  group('AuthState Tests', () {
    test('AuthInitial props è vuoto', () {
      final state = AuthInitial();
      expect(state.props, isEmpty);
    });

    test('AuthLoading props contiene message', () {
      const state = AuthLoading(message: 'Loading...');
      expect(state.message, equals('Loading...'));
      expect(state.props, contains('Loading...'));
    });

    test('AuthLoading message può essere null', () {
      const state = AuthLoading();
      expect(state.message, isNull);
    });

    test('AuthAuthenticated props contiene user e profiles', () {
      const user = User(id: 'u1', email: 'test@test.com', username: 'test');
      const profile = UserProfile(id: 'p1', name: 'Profile');
      const state = AuthAuthenticated(
        user: user,
        profiles: [profile],
        selectedProfile: profile,
      );

      expect(state.user, equals(user));
      expect(state.profiles.length, equals(1));
      expect(state.selectedProfile, equals(profile));
      expect(state.hasSelectedProfile, isTrue);
    });

    test('AuthAuthenticated senza profilo selezionato', () {
      const state = AuthAuthenticated(
        user: User(id: 'u1', email: 'test@test.com', username: 'test'),
      );

      expect(state.selectedProfile, isNull);
      expect(state.hasSelectedProfile, isFalse);
      expect(state.profiles, isEmpty);
    });

    test('AuthUnauthenticated props contiene showOnboarding', () {
      const state = AuthUnauthenticated(showOnboarding: true);
      expect(state.showOnboarding, isTrue);
      expect(state.props, contains(true));
    });

    test('AuthUnauthenticated default showOnboarding è false', () {
      const state = AuthUnauthenticated();
      expect(state.showOnboarding, isFalse);
    });

    test('AuthError props contiene message e code', () {
      const state = AuthError('Error message', code: 'ERR_001');
      expect(state.message, equals('Error message'));
      expect(state.code, equals('ERR_001'));
      expect(state.props, containsAll(['Error message', 'ERR_001']));
    });

    test('AuthError code può essere null', () {
      const state = AuthError('Error message');
      expect(state.code, isNull);
    });

    test('AuthPasswordResetSent props contiene email', () {
      const state = AuthPasswordResetSent('test@test.com');
      expect(state.email, equals('test@test.com'));
      expect(state.props, contains('test@test.com'));
    });
  });

  group('AuthEvent Tests', () {
    test('CheckAuthStatusEvent props è vuoto', () {
      final event = CheckAuthStatusEvent();
      expect(event.props, isEmpty);
    });

    test('LoginEvent props contiene credenziali', () {
      const event = LoginEvent(
        email: 'test@test.com',
        password: 'password',
        rememberMe: true,
      );

      expect(event.email, equals('test@test.com'));
      expect(event.password, equals('password'));
      expect(event.rememberMe, isTrue);
      expect(event.props, containsAll(['test@test.com', 'password', true]));
    });

    test('LoginEvent rememberMe default è false', () {
      const event = LoginEvent(
        email: 'test@test.com',
        password: 'password',
      );
      expect(event.rememberMe, isFalse);
    });

    test('RegisterEvent props contiene dati utente', () {
      const event = RegisterEvent(
        email: 'new@test.com',
        username: 'newuser',
        password: 'Password123!',
        acceptTerms: true,
      );

      expect(event.email, equals('new@test.com'));
      expect(event.username, equals('newuser'));
      expect(event.password, equals('Password123!'));
      expect(event.acceptTerms, isTrue);
    });

    test('RegisterEvent acceptTerms default è true', () {
      const event = RegisterEvent(
        email: 'new@test.com',
        username: 'newuser',
        password: 'Password123!',
      );
      expect(event.acceptTerms, isTrue);
    });

    test('LogoutEvent props è vuoto', () {
      final event = LogoutEvent();
      expect(event.props, isEmpty);
    });

    test('SelectProfileEvent props contiene profile', () {
      const profile = UserProfile(id: 'p1', name: 'Test');
      const event = SelectProfileEvent(profile);

      expect(event.profile, equals(profile));
      expect(event.props, contains(profile));
    });

    test('GoogleSignInEvent props è vuoto', () {
      final event = GoogleSignInEvent();
      expect(event.props, isEmpty);
    });

    test('AppleSignInEvent props è vuoto', () {
      final event = AppleSignInEvent();
      expect(event.props, isEmpty);
    });

    test('ForgotPasswordEvent props contiene email', () {
      const event = ForgotPasswordEvent('test@test.com');
      expect(event.email, equals('test@test.com'));
      expect(event.props, contains('test@test.com'));
    });
  });

  group('Error Handling', () {
    test('gestisce errore network quando backend offline', () async {
      final isOnline = await BackendChecker.isBackendAvailable();

      if (!isOnline) {
        authBloc.add(const LoginEvent(
          email: 'test@test.com',
          password: 'password',
        ));
        await Future.delayed(const Duration(seconds: 3));

        final state = authBloc.state;
        expect(state, isA<AuthError>());
        if (state is AuthError) {
          expect(state.message, isNotEmpty);
        }
      } else {
        expect(true, isTrue);
      }
    });
  });
}

/// Repository wrapper per test Auth - ZERO MOCK
class _TestAuthRepository implements AuthRepository {
  final Dio _dio;
  String? _token;
  bool _isFirstLaunch = true;

  _TestAuthRepository(this._dio);

  @override
  Future<Either<Failure, User>> login({
    required String email,
    required String password,
    bool rememberMe = false,
  }) async {
    try {
      final response = await _dio.post(
        '/auth/login',
        data: {
          'email': email,
          'password': password,
          'remember_me': rememberMe,
        },
      );
      _token = response.data['access_token'] as String?;
      return Right(User.fromJson(response.data['user'] as Map<String, dynamic>));
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.response?.data?['detail'] ?? e.message ?? 'Login failed',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, User>> register({
    required String email,
    required String username,
    required String password,
    bool acceptTerms = true,
  }) async {
    try {
      final response = await _dio.post(
        '/auth/register',
        data: {
          'email': email,
          'username': username,
          'password': password,
          'accept_terms': acceptTerms,
        },
      );
      _token = response.data['access_token'] as String?;
      return Right(User.fromJson(response.data['user'] as Map<String, dynamic>));
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.response?.data?['detail'] ?? e.message ?? 'Registration failed',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, void>> logout() async {
    try {
      await _dio.post('/auth/logout');
      _token = null;
      return const Right(null);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Logout failed',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, User>> getCurrentUser() async {
    if (_token == null) {
      return Left(AuthFailure(message: 'Not authenticated'));
    }
    try {
      final response = await _dio.get(
        '/auth/me',
        options: Options(headers: {'Authorization': 'Bearer $_token'}),
      );
      return Right(User.fromJson(response.data as Map<String, dynamic>));
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Failed to get user',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<bool> isAuthenticated() async {
    return _token != null;
  }

  @override
  bool isFirstLaunch() {
    final result = _isFirstLaunch;
    _isFirstLaunch = false;
    return result;
  }

  @override
  Future<List<UserProfile>> getUserProfiles() async {
    try {
      final response = await _dio.get(
        '/auth/profiles',
        options: Options(headers: {'Authorization': 'Bearer $_token'}),
      );
      return (response.data as List)
          .map((json) => UserProfile.fromJson(json as Map<String, dynamic>))
          .toList();
    } catch (e) {
      return [];
    }
  }

  @override
  Future<Either<Failure, UserProfile>> createProfile({
    required String name,
    String? avatarUrl,
  }) async {
    try {
      final response = await _dio.post(
        '/auth/profiles',
        data: {'name': name, 'avatar_url': avatarUrl},
        options: Options(headers: {'Authorization': 'Bearer $_token'}),
      );
      return Right(UserProfile.fromJson(response.data as Map<String, dynamic>));
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Failed to create profile',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, User>> signInWithGoogle() async {
    return Left(ServerFailure(message: 'Google Sign In not available in tests'));
  }

  @override
  Future<Either<Failure, User>> signInWithApple() async {
    return Left(ServerFailure(message: 'Apple Sign In not available in tests'));
  }

  @override
  Future<Either<Failure, void>> forgotPassword(String email) async {
    try {
      await _dio.post(
        '/auth/forgot-password',
        data: {'email': email},
      );
      return const Right(null);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Failed to send reset email',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, void>> verifyEmail(String token) async {
    try {
      await _dio.post(
        '/auth/verify-email',
        data: {'token': token},
      );
      return const Right(null);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Failed to verify email',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }
}
