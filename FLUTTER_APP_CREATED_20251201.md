# Flutter App - Enterprise Netflix-Style Streaming
**Data Creazione:** 1 Dicembre 2025
**Versione:** 1.0.0

---

## RIEPILOGO

Creata app Flutter enterprise-grade con UI stile Netflix per lo streaming di video di arti marziali.

---

## STRUTTURA PROGETTO

```
flutter_app/
├── lib/
│   ├── main.dart                           # Entry point
│   ├── core/
│   │   ├── config/
│   │   │   └── app_router.dart             # Go Router navigation
│   │   ├── di/
│   │   │   └── injection.dart              # GetIt dependency injection
│   │   ├── error/
│   │   │   ├── exceptions.dart             # Custom exceptions
│   │   │   └── failures.dart               # Failure classes (Either)
│   │   ├── network/
│   │   │   ├── api_client.dart             # Dio HTTP client + interceptors
│   │   │   └── network_info.dart           # Connectivity check
│   │   ├── theme/
│   │   │   └── app_theme.dart              # Netflix dark theme
│   │   └── utils/
│   │       └── bloc_observer.dart          # BLoC debugging
│   │
│   └── features/
│       ├── auth/
│       │   ├── domain/
│       │   │   ├── entities/user.dart      # User, UserProfile, UserTier
│       │   │   ├── repositories/           # Auth repository interface
│       │   │   └── usecases/               # Login, Register, Logout
│       │   └── presentation/
│       │       ├── bloc/auth_bloc.dart     # Authentication BLoC
│       │       └── pages/
│       │           ├── splash_page.dart    # Splash screen animato
│       │           └── login_page.dart     # Login form Netflix-style
│       │
│       ├── home/
│       │   ├── domain/
│       │   │   └── entities/content.dart   # VideoContent, ContentRow, Category
│       │   └── presentation/
│       │       ├── bloc/home_bloc.dart     # Home content BLoC
│       │       ├── pages/
│       │       │   ├── home_page.dart      # Home con hero banner
│       │       │   └── main_shell.dart     # Bottom navigation shell
│       │       └── widgets/
│       │           ├── hero_banner.dart    # Hero banner Netflix-style
│       │           └── content_row.dart    # Horizontal scrolling rows
│       │
│       └── player/
│           ├── domain/
│           │   └── entities/video_info.dart # Video metadata
│           └── presentation/
│               ├── bloc/player_bloc.dart    # Player state management
│               ├── pages/
│               │   └── player_page.dart     # Full-screen player
│               └── widgets/
│                   └── player_controls.dart # Custom controls overlay
│
├── assets/
│   ├── images/
│   ├── icons/
│   ├── animations/
│   └── fonts/
│
├── pubspec.yaml                             # Dependencies
└── README.md                                # Documentation
```

---

## FEATURES IMPLEMENTATE

### UI/UX Netflix-Style
- Dark theme con palette colori Netflix (rosso #E50914, nero #141414)
- Hero banner con gradiente e auto-play preview
- Content rows orizzontali (standard, large Top 10, wide, circular)
- Animazioni fluide con flutter_animate
- Shimmer loading skeletons
- Bottom navigation bar trasparente

### Video Player Enterprise
- Full-screen immersive mode
- Gesture controls:
  - Tap singolo: show/hide controls
  - Double tap laterale: skip ±10 secondi
  - Swipe orizzontale: seek
  - Swipe verticale: volume/brightness
- Playback speed control (0.25x - 2x)
- Progress bar con buffer indicator
- Lock screen mode
- Skeleton overlay toggle (per arti marziali)
- Subtitles support
- Quality selection

### Autenticazione
- Login email/password
- Social login (Google, Apple)
- JWT token management con refresh automatico
- Remember me
- Forgot password
- Multi-profile Netflix-style

### Architettura Clean Architecture
- Separation of concerns (data/domain/presentation)
- Repository pattern
- Use cases per business logic
- BLoC pattern per state management
- Dependency injection con GetIt

---

## DIPENDENZE CHIAVE

| Package | Versione | Utilizzo |
|---------|----------|----------|
| flutter_bloc | ^8.1.3 | State management |
| get_it | ^7.6.4 | Dependency injection |
| go_router | ^13.0.1 | Navigation |
| dio | ^5.4.0 | HTTP client |
| video_player | ^2.8.2 | Video playback |
| better_player | ^0.0.84 | Advanced player |
| cached_network_image | ^3.3.1 | Image caching |
| flutter_animate | ^4.3.0 | Animations |
| shimmer | ^3.0.0 | Loading skeletons |
| hive | ^2.2.3 | Local storage |
| flutter_secure_storage | ^9.0.0 | Secure token storage |
| firebase_core | ^2.24.2 | Firebase |
| flutter_stripe | ^10.1.1 | Payments |

---

## PROSSIMI STEP

### Per completare l'app:

1. **Creare file stub rimanenti:**
   - `register_page.dart` - Registrazione
   - `onboarding_page.dart` - Onboarding
   - `profile_page.dart` - Profilo utente
   - `profile_selector_page.dart` - Selezione profilo
   - `search_page.dart` - Ricerca
   - `downloads_page.dart` - Download offline
   - `settings_page.dart` - Impostazioni
   - `category_page.dart` - Pagina categoria
   - `video_details_page.dart` - Dettagli video
   - Widget aggiuntivi (category_tabs, top_app_bar, skeleton_overlay, etc.)

2. **Implementare data layer:**
   - Remote datasources con API calls
   - Local datasources con Hive
   - Repository implementations

3. **Configurare Firebase:**
   - Firebase Auth
   - Firebase Messaging (push notifications)
   - Firebase Analytics

4. **Testing:**
   - Unit tests per BLoCs
   - Widget tests per UI
   - Integration tests

---

## COMANDI UTILI

```bash
# Installare dipendenze
flutter pub get

# Generare codice (freezed, json_serializable)
flutter pub run build_runner build --delete-conflicting-outputs

# Run app in debug
flutter run

# Build release APK
flutter build apk --release

# Build iOS
flutter build ios --release
```

---

## BACKUP

Backup pre-Flutter creato in:
```
media-center-arti-marziali/backup_20251201_flutter/backup_pre_flutter_*.tar.gz
```

---

## INTEGRAZIONE CON BACKEND

L'app si connette al backend esistente:
- **Base URL:** `http://localhost:8100/api/v1`
- **Endpoints utilizzati:**
  - `POST /auth/login` - Login
  - `POST /auth/register` - Registrazione
  - `POST /auth/refresh` - Token refresh
  - `GET /videos/featured` - Contenuto in evidenza
  - `GET /videos/categories` - Categorie
  - `GET /videos/{id}/stream` - URL streaming
  - `GET /skeletons/{video_id}` - Dati skeleton per overlay
  - `POST /videos/{id}/progress` - Salva progresso

---

*Documento generato il 1 Dicembre 2025*
*File creati: 29 file Dart + pubspec.yaml + README.md*
*~3500 linee di codice*
