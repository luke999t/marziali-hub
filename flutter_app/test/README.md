# Enterprise Test Suite

## Overview

This is a comprehensive enterprise-grade test suite for the Martial Arts Streaming Flutter App.

**Targets:**
- **Coverage:** 90%+
- **Pass Rate:** 95%+

## Test Categories

### 1. Unit Tests (`@Tags(['unit'])`)
Tests individual components in isolation.

**Location:** `test/unit/`
- `features/auth/data/datasources/` - Data source tests
- `features/auth/data/repositories/` - Repository tests
- `features/auth/presentation/bloc/` - BLoC tests
- `core/network/` - Network layer tests

### 2. Integration Tests (`@Tags(['integration'])`)
Tests component interactions and user flows.

**Location:** `test/integration/`
- `auth/auth_flow_test.dart` - Complete auth flow

### 3. Regression Tests (`@Tags(['regression'])`)
Tests for previously fixed bugs to prevent recurrence.

**Location:** `test/regression/`
- `auth/auth_regression_test.dart` - Auth module regressions

### 4. Security Tests (`@Tags(['security'])`)
OWASP Top 10 compliance and security validation.

**Location:** `test/security/`
- `auth/auth_security_test.dart` - Auth security
- Injection prevention
- Cryptographic validation
- Access control tests

### 5. Penetration Tests (`@Tags(['penetration'])`)
Simulated attack vectors and defense validation.

**Location:** `test/security/penetration/`
- SQL injection tests
- XSS prevention tests
- CSRF protection tests
- Rate limiting validation

### 6. Slow Tests (`@Tags(['slow'])`)
Long-running performance and stress tests.

**Location:** `test/slow/`
- `performance_test.dart` - Performance benchmarks

### 7. Holistic Tests (`@Tags(['holistic'])`)
End-to-end user journeys and cross-cutting concerns.

**Location:** `test/holistic/`
- `app_holistic_test.dart` - Full app testing

### 8. Static Analysis (`@Tags(['static'])`)
Code quality and best practices validation.

**Location:** `test/static_analysis/`
- `code_quality_test.dart` - Code standards

## Running Tests

### Windows (PowerShell)
```powershell
# Run all tests
.\scripts\run_tests.ps1 -All

# Run specific categories
.\scripts\run_tests.ps1 -Unit
.\scripts\run_tests.ps1 -Integration
.\scripts\run_tests.ps1 -Security

# Generate coverage
.\scripts\run_tests.ps1 -Coverage

# Generate report
.\scripts\run_tests.ps1 -Report
```

### Unix/Mac (Bash)
```bash
# Run all tests
./scripts/run_tests.sh --all

# Run specific categories
./scripts/run_tests.sh --unit
./scripts/run_tests.sh --integration
./scripts/run_tests.sh --security

# Generate coverage
./scripts/run_tests.sh --coverage

# Generate report
./scripts/run_tests.sh --report
```

### Flutter Commands
```bash
# Run all tests
flutter test

# Run tests by tag
flutter test --tags=unit
flutter test --tags=security
flutter test --tags="unit,integration"

# Run with coverage
flutter test --coverage

# Run specific file
flutter test test/unit/features/auth/data/datasources/auth_remote_datasource_test.dart
```

## Test Configuration

### `dart_test.yaml`
Global test configuration including:
- Timeouts per test category
- Concurrency settings
- CI presets

### `analysis_options.yaml`
Strict linting rules for:
- Type safety
- Code style
- Best practices

## Test Mocks

### Location: `test/mocks/`
- `mock_repositories.dart` - Repository mocks and fixtures

### Available Mocks:
- `MockAuthRepository`
- `MockAuthRemoteDataSource`
- `MockAuthLocalDataSource`
- `MockNetworkInfo`
- `MockApiClient`

### Test Fixtures:
- `AuthTestFixtures` - Pre-configured test data
- `TestDataFactory` - Dynamic test data generation
- `SecurityTestPayloads` - Security test vectors

## Code Coverage

### Minimum Thresholds:
- Lines: 90%
- Functions: 90%
- Branches: 85%
- Statements: 90%

### Excluded from Coverage:
- `lib/generated/**`
- `lib/**/*.g.dart`
- `lib/**/*.freezed.dart`

### Generate HTML Report:
```bash
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html
open coverage/html/index.html
```

## CI/CD Integration

### GitHub Actions Example:
```yaml
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: subosito/flutter-action@v2
    - run: flutter pub get
    - run: flutter test --coverage
    - name: Check coverage
      run: |
        lcov --summary coverage/lcov.info
```

## Best Practices

### Writing Tests:
1. Use `@Tags()` to categorize tests
2. Follow AAA pattern (Arrange, Act, Assert)
3. Use descriptive test names
4. Mock external dependencies
5. Test edge cases and error scenarios

### Test Naming:
```dart
test('should return User when login is successful', () async {
  // ...
});

test('should throw AuthException when credentials are invalid', () async {
  // ...
});
```

### Using Mocks:
```dart
setUp(() {
  mockAuthRepository = MockAuthRepository();
  mockAuthRepository.stubLoginSuccess(testUser);
});
```

## Security Testing

### OWASP Coverage:
- A01:2021 - Broken Access Control ✓
- A02:2021 - Cryptographic Failures ✓
- A03:2021 - Injection ✓
- A04:2021 - Insecure Design ✓
- A05:2021 - Security Misconfiguration ✓
- A07:2021 - Identification Failures ✓
- A08:2021 - Software Integrity Failures ✓
- A09:2021 - Logging Failures ✓

## Performance Benchmarks

### Targets:
- Cold start: < 3 seconds
- Warm start: < 1 second
- Navigation: < 300ms
- API response: < 500ms
- Video start: < 2 seconds
- 60 FPS scrolling

## Troubleshooting

### Common Issues:

**Tests timeout:**
```bash
flutter test --timeout=120s
```

**Mock not working:**
```dart
setUpAll(() {
  registerFallbackValues();
});
```

**Coverage incomplete:**
```bash
flutter test --coverage --test-randomize-ordering-seed=random
```
