# CATALOGO MOBILE & FLUTTER
## Media Center Arti Marziali

**Data analisi**: 2025-12-13

---

## RIEPILOGO

| App | Framework | File |
|-----|-----------|------|
| Flutter App | Flutter/Dart | ~145 |
| Mobile App | React Native/Expo | ~20 |
| **TOTALE** | | **~165** |

---

# FLUTTER APP (flutter_app/)

## 1. STRUTTURA PROGETTO

```
flutter_app/
├── lib/
│   ├── main.dart              - Entry point
│   ├── core/                  - Core utilities
│   └── features/              - Feature modules
├── test/                      - Tests
├── pubspec.yaml               - Dependencies
└── android/ios/web/           - Platform folders
```

---

## 2. CORE (lib/core/)

### 2.1 Theme
```
theme/
└── app_theme.dart            - Material theme config
```

### 2.2 Config
```
config/
└── app_router.dart           - GoRouter navigation
```

### 2.3 Network
```
network/
├── api_client.dart           - Dio HTTP client
└── network_info.dart         - Connectivity check
```

### 2.4 Error Handling
```
error/
├── exceptions.dart           - Custom exceptions
└── failures.dart             - Failure types
```

### 2.5 Utils
```
utils/
└── bloc_observer.dart        - BLoC observer
```

### 2.6 Dependency Injection
```
di/
└── injection.dart            - GetIt DI setup
```

---

## 3. FEATURES (lib/features/)

### 3.1 Auth Feature
```
auth/
├── domain/
│   ├── entities/
│   │   └── user.dart                - User entity
│   ├── repositories/
│   │   └── auth_repository.dart     - Repository interface
│   └── usecases/
│       ├── login_usecase.dart
│       ├── register_usecase.dart
│       └── logout_usecase.dart
├── data/
│   ├── models/
│   │   ├── user_model.dart
│   │   └── auth_response_model.dart
│   ├── datasources/
│   │   ├── auth_remote_datasource.dart
│   │   └── auth_local_datasource.dart
│   └── repositories/
│       └── auth_repository_impl.dart
└── presentation/
    ├── bloc/
    │   └── auth_bloc.dart
    └── pages/
        ├── login_page.dart
        ├── register_page.dart
        └── splash_page.dart
```

### 3.2 Home Feature
```
home/
├── domain/
│   └── entities/
│       └── content.dart             - Content entity
├── presentation/
│   ├── bloc/
│   │   └── home_bloc.dart
│   ├── pages/
│   │   ├── home_page.dart
│   │   └── main_shell.dart          - Bottom nav shell
│   └── widgets/
│       ├── hero_banner.dart
│       └── content_row.dart
```

### 3.3 Player Feature
```
player/
├── domain/
│   └── entities/
│       └── video_info.dart
├── presentation/
│   ├── bloc/
│   │   └── player_bloc.dart
│   ├── pages/
│   │   └── player_page.dart
│   └── widgets/
│       └── player_controls.dart
```

### 3.4 Ads Feature
```
ads/
├── ads.dart                         - Feature barrel
├── domain/
│   ├── entities/
│   │   ├── pause_ad.dart
│   │   ├── sponsor_ad.dart
│   │   └── suggested_video.dart
│   ├── repositories/
│   │   └── ads_repository.dart
│   └── usecases/
│       ├── fetch_pause_ad_usecase.dart
│       ├── record_impression_usecase.dart
│       └── record_click_usecase.dart
├── data/
│   ├── models/
│   │   ├── pause_ad_model.dart
│   │   ├── sponsor_ad_model.dart
│   │   └── suggested_video_model.dart
│   ├── datasources/
│   │   └── ads_remote_datasource.dart
│   └── repositories/
│       └── ads_repository_impl.dart
└── presentation/
    ├── bloc/
    │   ├── pause_ad_bloc.dart
    │   ├── pause_ad_event.dart
    │   └── pause_ad_state.dart
    └── widgets/
        └── pause_ad_overlay.dart
```

### 3.5 Library Feature
```
library/
├── library.dart                     - Feature barrel
├── domain/
│   ├── entities/
│   │   └── library_item.dart
│   ├── repositories/
│   │   └── library_repository.dart
│   └── usecases/
│       ├── get_library_usecase.dart
│       ├── add_to_library_usecase.dart
│       └── remove_from_library_usecase.dart
├── data/
│   ├── models/
│   │   └── library_item_model.dart
│   ├── datasources/
│   │   ├── library_remote_datasource.dart
│   │   └── library_local_datasource.dart
│   └── repositories/
│       └── library_repository_impl.dart
└── presentation/
    ├── bloc/
    │   ├── library_bloc.dart
    │   ├── library_event.dart
    │   └── library_state.dart
    ├── pages/
    │   └── library_page.dart
    └── widgets/
        └── library_item_card.dart
```

### 3.6 Profile Feature
```
profile/
├── presentation/
│   ├── bloc/
│   │   └── profile_bloc.dart
│   └── pages/
│       ├── profile_page.dart
│       └── profile_selector_page.dart
```

### 3.7 Downloads Feature
```
downloads/
├── domain/
│   ├── entities/
│   │   └── download_item.dart
│   └── repositories/
│       └── downloads_repository.dart
├── data/
│   ├── models/
│   │   └── download_item_model.dart
│   └── datasources/
│       └── downloads_local_datasource.dart
└── presentation/
    ├── bloc/
    │   └── downloads_bloc.dart
    └── pages/
        └── downloads_page.dart
```

### 3.8 Search Feature
```
search/
├── domain/
│   ├── entities/
│   │   └── search_result.dart
│   └── repositories/
│       └── search_repository.dart
├── data/
│   ├── models/
│   │   └── search_result_model.dart
│   └── datasources/
│       └── search_remote_datasource.dart
└── presentation/
    └── pages/
        └── search_page.dart
```

### 3.9 Settings Feature
```
settings/
├── settings.dart                    - Feature barrel
├── domain/
│   ├── entities/
│   │   └── app_settings.dart
│   ├── repositories/
│   │   └── settings_repository.dart
│   └── usecases/
│       └── get_settings_usecase.dart
├── data/
│   ├── models/
│   │   └── app_settings_model.dart
│   ├── datasources/
│   │   ├── settings_local_datasource.dart
│   │   └── settings_remote_datasource.dart
│   └── repositories/
│       └── settings_repository_impl.dart
└── presentation/
    ├── bloc/
    │   ├── settings_bloc.dart
    │   ├── settings_event.dart
    │   └── settings_state.dart
    └── pages/
        └── settings_page.dart
```

### 3.10 Notifications Feature
```
notifications/
├── notifications.dart               - Feature barrel
├── domain/
│   ├── entities/
│   │   └── notification.dart
│   ├── repositories/
│   │   └── notifications_repository.dart
│   └── usecases/
│       └── notification_usecases.dart
├── data/
│   ├── models/
│   │   └── notification_model.dart
│   ├── datasources/
│   │   └── notifications_remote_datasource.dart
│   └── repositories/
│       └── notifications_repository_impl.dart
└── presentation/
    ├── bloc/
    │   └── notifications_bloc.dart
    └── pages/
        └── notifications_page.dart
```

---

## 4. ARCHITETTURA FLUTTER

```
CLEAN ARCHITECTURE:
├── Domain Layer (entities, repositories interfaces, usecases)
├── Data Layer (models, datasources, repository implementations)
└── Presentation Layer (bloc, pages, widgets)

STATE MANAGEMENT:
- flutter_bloc per stato

DEPENDENCY INJECTION:
- get_it per DI

NAVIGATION:
- go_router per routing

HTTP:
- dio per API calls
```

---

# MOBILE APP (mobile/)

## 1. STRUTTURA

```
mobile/
├── src/
│   ├── screens/           - Schermate
│   ├── components/        - Componenti
│   ├── contexts/          - React contexts
│   ├── hooks/             - Custom hooks
│   ├── services/          - API services
│   └── navigation/        - Navigation setup
├── App.tsx               - Entry point
└── package.json          - Dependencies
```

---

## 2. SCREENS (src/screens/)

```
HomeScreen.tsx            - Home feed
LoginScreen.tsx           - Login
RegisterScreen.tsx        - Registrazione
SearchScreen.tsx          - Ricerca
ProfileScreen.tsx         - Profilo utente
LibraryScreen.tsx         - Libreria personale
TechniquePlayerScreen.tsx - Player tecniche
AICoachScreen.tsx         - Coach AI
LiveStreamScreen.tsx      - Live streaming
OfflineVideosScreen.tsx   - Video offline
```

---

## 3. COMPONENTS (src/components/)

```
PauseAdOverlay.tsx        - Overlay ads pausa
```

---

## 4. CONTEXTS (src/contexts/)

```
AuthContext.tsx           - Auth state
I18nContext.tsx           - i18n
```

---

## 5. HOOKS (src/hooks/)

```
useNotifications.ts       - Push notifications
useOfflineDownload.ts     - Download offline
```

---

## 6. SERVICES (src/services/)

```
api.ts                    - API client
notifications.ts          - Push service
offlineStorage.ts         - Storage offline
adsService.ts             - Ads service
```

---

## 7. NAVIGATION (src/navigation/)

```
RootNavigator.tsx         - Root navigator con tabs
```

---

## CONFRONTO APPS

| Feature | Flutter | Mobile (RN) |
|---------|---------|-------------|
| Screens | ~10 | 10 |
| State | BLoC | Context |
| Architecture | Clean | MVC |
| DI | get_it | - |
| HTTP | Dio | Fetch |
| Features | Full | Basic |

---

## METRICHE

| Metrica | Flutter | Mobile |
|---------|---------|--------|
| File Dart/TSX | ~145 | ~20 |
| Features | 10 | 5 |
| Pages | 10 | 10 |
| Architecture | Clean | Basic |

---

*Catalogo generato il 2025-12-13*
