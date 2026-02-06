/// ============================================================================
/// TEST CONFIGURATION
/// ============================================================================
///
/// AI_MODULE: TestConfig
/// AI_DESCRIPTION: Configuration constants for E2E integration tests
/// AI_BUSINESS: Centralizes test configuration for maintainability
/// AI_TEACHING: Single source of truth for test settings
///
/// ============================================================================
library;

/// API Configuration
class ApiConfig {
  static const String baseUrl = 'http://localhost:8000/api/v1';
  static const String healthEndpoint = 'http://localhost:8000/health';

  /// Timeout durations
  static const Duration apiTimeout = Duration(seconds: 10);
  static const Duration longApiTimeout = Duration(seconds: 30);
}

/// Test Timeouts
class TestTimeouts {
  /// Widget settle timeout
  static const Duration settle = Duration(seconds: 2);

  /// Animation completion timeout
  static const Duration animation = Duration(milliseconds: 500);

  /// Page load timeout
  static const Duration pageLoad = Duration(seconds: 5);

  /// Login/Register flow timeout
  static const Duration authFlow = Duration(seconds: 10);

  /// Video player initialization
  static const Duration playerInit = Duration(seconds: 8);

  /// Network request timeout
  static const Duration network = Duration(seconds: 15);

  /// Infinite scroll load more
  static const Duration loadMore = Duration(seconds: 3);

  /// Pull to refresh
  static const Duration pullRefresh = Duration(seconds: 5);
}

/// Test Widget Keys
/// Using semantic keys for reliable widget finding
class TestKeys {
  // Auth
  static const String loginEmailField = 'login_email_field';
  static const String loginPasswordField = 'login_password_field';
  static const String loginButton = 'login_button';
  static const String registerButton = 'register_button';
  static const String forgotPasswordLink = 'forgot_password_link';

  static const String registerEmailField = 'register_email_field';
  static const String registerPasswordField = 'register_password_field';
  static const String registerConfirmPasswordField = 'register_confirm_password_field';
  static const String registerNameField = 'register_name_field';
  static const String registerSubmitButton = 'register_submit_button';

  // Navigation
  static const String bottomNavHome = 'bottom_nav_home';
  static const String bottomNavSearch = 'bottom_nav_search';
  static const String bottomNavEvents = 'bottom_nav_events';
  static const String bottomNavProfile = 'bottom_nav_profile';

  // Home
  static const String homeScrollView = 'home_scroll_view';
  static const String featuredCarousel = 'featured_carousel';
  static const String categorySection = 'category_section';
  static const String videoCard = 'video_card';

  // Player
  static const String videoPlayer = 'video_player';
  static const String playPauseButton = 'play_pause_button';
  static const String seekBar = 'seek_bar';
  static const String fullscreenButton = 'fullscreen_button';
  static const String qualityButton = 'quality_button';
  static const String skeletonOverlay = 'skeleton_overlay';

  // Profile
  static const String profileAvatar = 'profile_avatar';
  static const String profileName = 'profile_name';
  static const String editProfileButton = 'edit_profile_button';
  static const String watchHistoryList = 'watch_history_list';
  static const String favoritesList = 'favorites_list';
  static const String settingsButton = 'settings_button';
  static const String logoutButton = 'logout_button';

  // Events
  static const String eventsList = 'events_list';
  static const String eventCard = 'event_card';
  static const String eventDetailView = 'event_detail_view';
  static const String subscribeButton = 'subscribe_button';
  static const String unsubscribeButton = 'unsubscribe_button';
  static const String myEventsTab = 'my_events_tab';

  // Search
  static const String searchField = 'search_field';
  static const String searchResults = 'search_results';
  static const String searchFilters = 'search_filters';
  static const String searchHistory = 'search_history';
  static const String noResultsMessage = 'no_results_message';
}

/// Route names matching app_router.dart
class TestRoutes {
  static const String splash = '/';
  static const String login = '/login';
  static const String register = '/register';
  static const String forgotPassword = '/forgot-password';
  static const String home = '/home';
  static const String search = '/search';
  static const String player = '/player';
  static const String profile = '/profile';
  static const String settings = '/settings';
  static const String events = '/events';
  static const String eventDetail = '/events/:id';
  static const String downloads = '/downloads';
  static const String notifications = '/notifications';
  static const String fusion = '/fusion';
}

/// Error messages to verify
class ExpectedMessages {
  // Auth errors
  static const String invalidCredentials = 'Credenziali non valide';
  static const String emailRequired = 'Email obbligatoria';
  static const String passwordRequired = 'Password obbligatoria';
  static const String passwordTooShort = 'Password troppo corta';
  static const String emailInvalid = 'Email non valida';
  static const String passwordMismatch = 'Le password non coincidono';

  // Network errors
  static const String networkError = 'Errore di rete';
  static const String serverError = 'Errore del server';
  static const String timeout = 'Timeout';

  // Success messages
  static const String loginSuccess = 'Login effettuato';
  static const String registerSuccess = 'Registrazione completata';
  static const String profileUpdated = 'Profilo aggiornato';
  static const String subscribed = 'Iscrizione confermata';
  static const String unsubscribed = 'Iscrizione annullata';
}
