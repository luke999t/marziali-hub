/// ============================================================================
/// TEST DATA
/// ============================================================================
///
/// AI_MODULE: TestData
/// AI_DESCRIPTION: Test fixtures and data for E2E integration tests
/// AI_BUSINESS: Provides consistent test data across all test flows
/// AI_TEACHING: ZERO MOCK - uses real backend data when possible
///
/// ============================================================================
library;

/// Test User Credentials
/// These users should exist in the test database
class TestUsers {
  /// Primary test user for most flows
  static const TestUser primary = TestUser(
    email: 'test@example.com',
    password: 'TestPassword123!',
    name: 'Test User',
  );

  /// Secondary user for multi-user scenarios
  static const TestUser secondary = TestUser(
    email: 'test2@example.com',
    password: 'TestPassword123!',
    name: 'Test User 2',
  );

  /// Admin user for ASD dashboard tests
  static const TestUser admin = TestUser(
    email: 'asd_admin@test.com',
    password: 'TestPassword123!',
    name: 'ASD Admin',
  );

  /// New user for registration tests
  static TestUser newUser() => TestUser(
    email: 'new_user_${DateTime.now().millisecondsSinceEpoch}@test.com',
    password: 'NewPassword123!',
    name: 'New Test User',
  );

  /// Invalid credentials for error testing
  static const TestUser invalid = TestUser(
    email: 'nonexistent@test.com',
    password: 'WrongPassword123!',
    name: 'Invalid User',
  );
}

/// Test user data structure
class TestUser {
  final String email;
  final String password;
  final String name;

  const TestUser({
    required this.email,
    required this.password,
    required this.name,
  });
}

/// Test Video Data
class TestVideos {
  /// A sample video that should exist in the database
  static const TestVideo sample = TestVideo(
    id: 'sample-video-001',
    title: 'Sample Training Video',
    duration: Duration(minutes: 10, seconds: 30),
    category: 'Kung Fu',
  );

  /// Video with skeleton overlay data
  static const TestVideo withSkeleton = TestVideo(
    id: 'skeleton-video-001',
    title: 'Video with Skeleton Analysis',
    duration: Duration(minutes: 5),
    category: 'Tai Chi',
    hasSkeleton: true,
  );

  /// Long video for seeking tests
  static const TestVideo longVideo = TestVideo(
    id: 'long-video-001',
    title: 'Long Form Training',
    duration: Duration(hours: 1, minutes: 30),
    category: 'Full Course',
  );
}

class TestVideo {
  final String id;
  final String title;
  final Duration duration;
  final String category;
  final bool hasSkeleton;

  const TestVideo({
    required this.id,
    required this.title,
    required this.duration,
    required this.category,
    this.hasSkeleton = false,
  });
}

/// Test Event Data
class TestEvents {
  /// An upcoming event
  static TestEvent upcoming = TestEvent(
    id: 'event-upcoming-001',
    title: 'Stage Kung Fu Milano',
    startDate: DateTime.now().add(const Duration(days: 30)),
    endDate: DateTime.now().add(const Duration(days: 32)),
    location: 'Milano',
    price: 9900, // cents
    capacity: 50,
  );

  /// Event that is full
  static TestEvent soldOut = TestEvent(
    id: 'event-soldout-001',
    title: 'Workshop Tai Chi',
    startDate: DateTime.now().add(const Duration(days: 15)),
    endDate: DateTime.now().add(const Duration(days: 15)),
    location: 'Roma',
    price: 4900,
    capacity: 30,
    isSoldOut: true,
  );

  /// Past event
  static TestEvent past = TestEvent(
    id: 'event-past-001',
    title: 'Seminario Passato',
    startDate: DateTime.now().subtract(const Duration(days: 30)),
    endDate: DateTime.now().subtract(const Duration(days: 29)),
    location: 'Napoli',
    price: 7500,
    capacity: 40,
    isPast: true,
  );
}

class TestEvent {
  final String id;
  final String title;
  final DateTime startDate;
  final DateTime endDate;
  final String location;
  final int price; // in cents
  final int capacity;
  final bool isSoldOut;
  final bool isPast;

  TestEvent({
    required this.id,
    required this.title,
    required this.startDate,
    required this.endDate,
    required this.location,
    required this.price,
    required this.capacity,
    this.isSoldOut = false,
    this.isPast = false,
  });

  String get formattedPrice => '€${(price / 100).toStringAsFixed(2)}';
}

/// Test Search Queries
class TestSearchQueries {
  /// Query that should return results
  static const String withResults = 'kung fu';

  /// Query that should return no results
  static const String noResults = 'xyz123nonexistent';

  /// Category filter
  static const String categoryFilter = 'Tai Chi';

  /// Query for recent/popular
  static const String popular = 'training';
}

/// Profile Update Data
class TestProfileData {
  static const String newName = 'Updated Test Name';
  static const String newBio = 'This is an updated bio for testing';

  /// Password change test data
  static const String currentPassword = 'TestPassword123!';
  static const String newPassword = 'NewTestPassword456!';
}

/// Test Categories
class TestCategories {
  static const List<String> all = [
    'Kung Fu',
    'Tai Chi',
    'Wing Chun',
    'Shaolin',
    'Wushu',
    'Qi Gong',
  ];

  static const String first = 'Kung Fu';
  static const String second = 'Tai Chi';
}

/// Helper functions for test data
class TestDataHelpers {
  /// Generate unique email for registration tests
  static String uniqueEmail() {
    return 'test_${DateTime.now().millisecondsSinceEpoch}@test.com';
  }

  /// Generate unique event title
  static String uniqueEventTitle() {
    return 'Test Event ${DateTime.now().millisecondsSinceEpoch}';
  }

  /// Format date for display comparison
  static String formatDate(DateTime date) {
    return '${date.day.toString().padLeft(2, '0')}/${date.month.toString().padLeft(2, '0')}/${date.year}';
  }

  /// Format price from cents
  static String formatPrice(int cents) {
    return '€${(cents / 100).toStringAsFixed(2)}';
  }
}
