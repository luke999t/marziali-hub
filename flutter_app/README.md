# Martial Arts Streaming - Flutter App

## Enterprise Netflix-Style Streaming Platform for Martial Arts

### Overview

This is a cross-platform (iOS/Android) streaming application built with Flutter, designed with a Netflix-style UI/UX for streaming martial arts instructional videos.

### Architecture

The app follows **Clean Architecture** with **BLoC pattern** for state management:

```
lib/
├── core/                          # Core utilities and configurations
│   ├── config/                    # App configuration (routes, env)
│   ├── constants/                 # App-wide constants
│   ├── di/                        # Dependency injection
│   ├── error/                     # Exception and failure handling
│   ├── network/                   # API client and network info
│   ├── theme/                     # Netflix-style theming
│   └── utils/                     # Utility classes
│
├── features/                      # Feature modules
│   ├── auth/                      # Authentication
│   │   ├── data/                  # Data layer
│   │   │   ├── datasources/       # Remote and local data sources
│   │   │   ├── models/            # Data models (DTOs)
│   │   │   └── repositories/      # Repository implementations
│   │   ├── domain/                # Domain layer
│   │   │   ├── entities/          # Business entities
│   │   │   ├── repositories/      # Repository interfaces
│   │   │   └── usecases/          # Business logic use cases
│   │   └── presentation/          # Presentation layer
│   │       ├── bloc/              # BLoC state management
│   │       ├── pages/             # Screen widgets
│   │       └── widgets/           # Reusable UI components
│   │
│   ├── home/                      # Home screen with content rows
│   ├── player/                    # Video player with skeleton overlay
│   ├── profile/                   # User profiles (Netflix multi-profile)
│   ├── search/                    # Search functionality
│   ├── downloads/                 # Offline downloads
│   ├── library/                   # Content library
│   ├── live/                      # Live streaming events
│   ├── notifications/             # Push notifications
│   ├── settings/                  # App settings
│   └── onboarding/                # First-time user onboarding
│
└── main.dart                      # App entry point
```

### Features

#### Core Features
- **Netflix-style UI/UX**: Dark theme, hero banners, horizontal content rows
- **HLS Adaptive Streaming**: Quality auto-adjustment based on network
- **Skeleton Overlay**: MediaPipe pose visualization during playback
- **Multi-profile Support**: Netflix-style profile selection
- **Offline Downloads**: Download videos for offline viewing
- **Live Streaming**: Real-time event streaming with chat

#### Authentication
- Email/Password login
- Social login (Google, Apple)
- JWT token management with refresh
- Biometric authentication

#### Video Player
- Full-screen immersive playback
- Gesture controls (swipe seek, brightness, volume)
- Playback speed control (0.25x - 2x)
- Picture-in-Picture support
- Chromecast support
- Subtitles (multi-language)
- Multiple audio tracks

#### Content Features
- Featured hero banner with auto-play preview
- Horizontal scrolling content rows
- Top 10 rankings with numbered cards
- Continue Watching with progress tracking
- My List (favorites)
- Categories by martial art style and level

### Tech Stack

| Category | Technology |
|----------|------------|
| **Framework** | Flutter 3.16+ |
| **State Management** | flutter_bloc |
| **Dependency Injection** | get_it + injectable |
| **Navigation** | go_router |
| **Networking** | dio + retrofit |
| **Local Storage** | hive + flutter_secure_storage |
| **Video Player** | video_player + better_player |
| **Push Notifications** | Firebase Messaging |
| **Analytics** | Firebase Analytics |
| **Payments** | flutter_stripe + in_app_purchase |

### Getting Started

#### Prerequisites
- Flutter SDK 3.16+
- Dart 3.2+
- Android Studio / Xcode
- Firebase project configured

#### Installation

```bash
# Clone the repository
cd flutter_app

# Get dependencies
flutter pub get

# Generate code (freezed, json_serializable, injectable)
flutter pub run build_runner build --delete-conflicting-outputs

# Run the app
flutter run
```

#### Environment Configuration

Create `.env` files for different environments:

```env
# .env.development
API_BASE_URL=http://localhost:8100/api/v1
STRIPE_PUBLISHABLE_KEY=pk_test_...

# .env.production
API_BASE_URL=https://api.yourdomain.com/api/v1
STRIPE_PUBLISHABLE_KEY=pk_live_...
```

### Project Structure Details

#### Core Layer

**Theme (`core/theme/app_theme.dart`)**
- Netflix color palette (dark theme)
- Custom text styles
- Component themes (buttons, cards, etc.)

**Network (`core/network/api_client.dart`)**
- Dio HTTP client with interceptors
- Automatic token refresh
- Error handling and mapping

**DI (`core/di/injection.dart`)**
- GetIt service locator
- Lazy singleton registration
- Factory registration for BLoCs

#### Feature Modules

Each feature follows the same structure:

```
feature/
├── data/
│   ├── datasources/
│   │   ├── feature_remote_datasource.dart
│   │   └── feature_local_datasource.dart
│   ├── models/
│   │   └── feature_model.dart (with fromJson/toJson)
│   └── repositories/
│       └── feature_repository_impl.dart
├── domain/
│   ├── entities/
│   │   └── feature_entity.dart
│   ├── repositories/
│   │   └── feature_repository.dart (interface)
│   └── usecases/
│       └── get_feature_usecase.dart
└── presentation/
    ├── bloc/
    │   └── feature_bloc.dart
    ├── pages/
    │   └── feature_page.dart
    └── widgets/
        └── feature_widget.dart
```

### Testing

```bash
# Unit tests
flutter test

# Integration tests
flutter test integration_test/

# Test coverage
flutter test --coverage
```

### Build & Release

```bash
# Build APK
flutter build apk --release

# Build App Bundle (Play Store)
flutter build appbundle --release

# Build iOS (requires macOS)
flutter build ipa --release
```

### API Integration

The app connects to the Media Center backend API:

| Endpoint | Description |
|----------|-------------|
| `POST /auth/login` | User authentication |
| `GET /videos/featured` | Featured content |
| `GET /videos/categories` | Content categories |
| `GET /videos/{id}/stream` | Video stream URL |
| `GET /skeletons/{video_id}` | Skeleton data for overlay |
| `POST /videos/{id}/progress` | Save watch progress |

### License

Proprietary - All rights reserved

---

*Built with Flutter - Enterprise Streaming Platform*
*Version 1.0.0 - December 2025*
