# Integration Test Suite

## Overview

This directory contains the complete E2E integration test suite for the Media Center Arti Marziali Flutter app. The tests follow the **ZERO MOCK** policy and require a running backend server.

## Test Statistics

| Category | Test Count | Description |
|----------|-----------|-------------|
| Auth Flow | 10 | Login, register, logout, session |
| Home/Browse | 8 | Home screen, infinite scroll, categories |
| Video Player | 12 | Playback, controls, skeleton overlay |
| Profile | 8 | View, edit, history, favorites |
| Events | 7 | Browse, details, subscription |
| Search | 5 | Search, filters, history |
| **Total** | **50** | Complete E2E coverage |

## Directory Structure

```
integration_test/
├── app_test.dart              # Main test runner
├── README.md                  # This file
├── helpers/
│   ├── test_config.dart       # Configuration constants
│   └── test_data.dart         # Test fixtures and data
├── robots/
│   ├── robots.dart            # Barrel export file
│   ├── base_robot.dart        # Base robot class
│   ├── auth_robot.dart        # Authentication page object
│   ├── home_robot.dart        # Home/browse page object
│   ├── player_robot.dart      # Video player page object
│   ├── profile_robot.dart     # Profile page object
│   ├── events_robot.dart      # Events page object
│   └── search_robot.dart      # Search page object
└── flows/
    ├── auth_flow_test.dart    # Authentication tests
    ├── home_flow_test.dart    # Home/browse tests
    ├── video_flow_test.dart   # Video player tests
    ├── profile_flow_test.dart # Profile tests
    ├── events_flow_test.dart  # Events tests
    └── search_flow_test.dart  # Search tests
```

## Prerequisites

### 1. Backend Server

The tests require the backend server running at `http://localhost:8000`.

```bash
# Start backend
cd ../backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### 2. Test User

Ensure test users exist in the database:

- **Primary**: test@example.com / TestPassword123!
- **Admin**: asd_admin@test.com / TestPassword123!

### 3. Flutter Dependencies

```bash
flutter pub get
```

## Running Tests

### Run All Tests

```bash
flutter test integration_test/app_test.dart
```

### Run Specific Flow

```bash
# Auth tests only
flutter test integration_test/flows/auth_flow_test.dart

# Video player tests only
flutter test integration_test/flows/video_flow_test.dart
```

### Run with Device/Emulator

```bash
# Android
flutter drive --target=integration_test/app_test.dart

# iOS
flutter drive --target=integration_test/app_test.dart --driver=test_driver/integration_test.dart

# Chrome (web)
flutter drive --target=integration_test/app_test.dart -d chrome
```

### Run with Coverage

```bash
flutter test integration_test/ --coverage
```

## Architecture

### Page Object Pattern (Robots)

Each robot class encapsulates interactions with a specific screen:

```dart
class AuthRobot extends BaseRobot {
  Future<void> login(TestUser user) async {
    await enterLoginEmail(user.email);
    await enterLoginPassword(user.password);
    await tapLoginButton();
    await settle(TestTimeouts.authFlow);
  }
}
```

### Test Structure

```dart
testWidgets('Login with valid credentials', (tester) async {
  authRobot = AuthRobot(tester);
  homeRobot = HomeRobot(tester);

  // Given: User is on login screen
  await authRobot.verifyLoginScreenVisible();

  // When: User logs in with valid credentials
  await authRobot.login(TestUsers.primary);

  // Then: User is redirected to home
  await homeRobot.verifyHomeScreenVisible();
});
```

## Configuration

### Test Timeouts (test_config.dart)

```dart
class TestTimeouts {
  static const Duration settle = Duration(seconds: 2);
  static const Duration pageLoad = Duration(seconds: 5);
  static const Duration authFlow = Duration(seconds: 10);
  static const Duration playerInit = Duration(seconds: 8);
  static const Duration network = Duration(seconds: 15);
}
```

### Test Data (test_data.dart)

```dart
class TestUsers {
  static const TestUser primary = TestUser(
    email: 'test@example.com',
    password: 'TestPassword123!',
    name: 'Test User',
  );
}
```

## ZERO MOCK Policy

⚠️ **Important**: These tests follow a strict ZERO MOCK policy:

1. **Real Backend**: All API calls go to the actual backend
2. **Real Database**: Tests interact with real (test) data
3. **No Mocking**: No HTTP mocks or fake responses
4. **Backend Required**: Tests fail if backend is not running

### Why ZERO MOCK?

- Tests verify actual integration between app and backend
- Catches real API contract issues
- More confidence in production readiness
- Matches real user experience

## Best Practices

### 1. Wait for Elements

```dart
// Good: Wait for specific element
await waitForText('Welcome');

// Bad: Fixed delay
await Future.delayed(Duration(seconds: 2));
```

### 2. Use Semantic Finders

```dart
// Good: Semantic finder
final loginButton = find.widgetWithText(ElevatedButton, 'Login');

// Acceptable: Icon finder
final homeTab = find.byIcon(Icons.home);

// Avoid: Index-based finder
final button = find.byType(ElevatedButton).at(0);
```

### 3. Clean State

```dart
tearDown(() async {
  // Reset test state after each test
  await authRobot.logout();
});
```

### 4. Descriptive Test Names

```dart
// Good: Describes behavior and expected outcome
testWidgets('Login with invalid password shows error message', ...);

// Bad: Vague description
testWidgets('Test login', ...);
```

## Troubleshooting

### Backend Connection Failed

```
Error: Backend not reachable at http://localhost:8000
```

**Solution**: Start the backend server.

### Test User Not Found

```
Error: Login failed - user not found
```

**Solution**: Create test users in the database or use seed script.

### Element Not Found

```
Error: Widget not found: Text("Login")
```

**Solution**: Check if the app is using different text or verify screen loaded correctly.

### Timeout Exceeded

```
Error: Timeout waiting for widget
```

**Solution**: Increase timeout or check for loading issues.

## Contributing

1. Follow the robot pattern for new screens
2. Add tests to appropriate flow files
3. Update this README with new test counts
4. Ensure all tests pass before PR

## Contact

For questions about the test suite, contact the development team.
