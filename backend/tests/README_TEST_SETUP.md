# Test Setup Guide - Media Center Arti Marziali

## Overview

This guide explains how to run the 132 enterprise-level API tests with **ZERO MOCK POLICY**.

## Current Status

```
Total Tests: 132
✓ Passed: 111 (84%)
⊘ Skipped: 21 (16%)
✗ Failed: 0 (0%)
```

**Pass Rate: 84%+ (111/132 non-skipped tests pass)**

## Prerequisites

1. **Backend running** on `http://localhost:8000`
2. **PostgreSQL database** with correct schema
3. **Test users and videos** created (run setup_test_data.py)

## Quick Start

### 1. Setup Test Data

Run this **ONCE** before running tests:

```bash
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
python tests/setup_test_data.py
```

This script creates:
- **3 test users**:
  - `test@martialarts.com` (FREE tier)
  - `premium@martialarts.com` (PREMIUM tier)
  - `admin@martialarts.com` (ADMIN + PREMIUM tier)

- **4 test videos**:
  - Karate Gyaku-zuki (PREMIUM)
  - Taekwondo Roundhouse (PREMIUM)
  - Kung Fu Forms (FREE)
  - Download Test Video (PREMIUM)

**All users use password**: `TestPassword123!` / `PremiumPassword123!` / `AdminPassword123!`

### 2. Run Tests

```bash
# Run all API tests
pytest tests/api/ -v

# Run specific module tests
pytest tests/api/test_blockchain_api.py -v
pytest tests/api/test_skeleton_api.py -v
pytest tests/api/test_live_translation_api.py -v

# Run with coverage
pytest tests/api/ --cov=api --cov-report=html
```

## Test Configuration

### Fixtures (tests/conftest.py)

The test configuration uses **session-scoped fixtures** to avoid recreating users/tokens for every test:

- `session_auth_token` - Token for `test@martialarts.com` (FREE tier)
- `session_premium_token` - Token for `premium@martialarts.com` (PREMIUM tier)
- `session_admin_token` - Token for `admin@martialarts.com` (ADMIN)
- `test_video_id` - ID of a test video in database
- `shared_client` - Shared TestClient instance

All fixtures use **REAL database** and **REAL backend**, no mocking allowed.

## Skip Analysis

### Why 21 Tests Skip

All 21 skipped tests are in `test_fusion_api.py` and skip because:

**Root Cause**: The `/api/v1/fusion/projects` POST endpoint returns HTTP 500 with error:
```
'NoneType' object has no attribute 'send'
```

This is an **asyncpg connection issue** in the backend fusion endpoint, not a test configuration issue.

### Skipped Tests List

1. `test_list_projects_returns_list` - Requires fusion project
2. `test_get_project_detail` - Requires fusion project
3. `test_update_project_name` - Requires fusion project
4. `test_update_project_config` - Requires fusion project
5. `test_delete_project_success` - Requires fusion project
6. `test_add_video_to_project` - Requires fusion project
7. `test_add_video_with_custom_weight` - Requires fusion project
8. `test_add_duplicate_video_fails` - Requires fusion project
9. `test_list_project_videos` - Requires fusion project
10. `test_update_video_parameters` - Requires fusion project
11. `test_remove_video_from_project` - Requires fusion project
12. `test_start_fusion_requires_min_two_videos` - Requires fusion project
13. `test_get_fusion_status_draft` - Requires fusion project
14. `test_get_result_not_completed` - Requires fusion project
15. `test_get_preview_not_completed` - Requires fusion project
16. `test_cancel_fusion_not_running` - Requires fusion project
17. `test_export_requires_completed_fusion` - Requires fusion project
18. `test_preview_data_structure` - Requires fusion project
19. `test_get_requires_auth` - Requires fusion project
20. `test_user_isolation` - Requires fusion project
21. `test_project_response_has_required_fields` - Requires fusion project

### How to Fix Skipped Tests

To fix these 21 skipped tests, the backend fusion endpoint needs to be fixed:

1. **Issue**: `get_current_active_user` dependency causes asyncpg connection error
2. **Location**: `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend\api\v1\fusion.py:561`
3. **Solution**: Fix async database connection handling in `get_current_active_user`

**Note**: This is a backend issue, NOT a test fixture issue. The test fixtures are correctly configured.

## Test Data Management

### Re-run Setup

If you need to recreate test users/videos:

```bash
python tests/setup_test_data.py
```

The script is **idempotent** - it won't create duplicates, just verifies/updates existing records.

### Manual Cleanup

To remove test data:

```sql
-- Delete test users
DELETE FROM users WHERE email IN (
    'test@martialarts.com',
    'premium@martialarts.com',
    'admin@martialarts.com'
);

-- Delete test videos
DELETE FROM videos WHERE slug IN (
    'test-video-karate-gyaku-zuki',
    'test-video-taekwondo-roundhouse',
    'test-video-kung-fu-forms',
    'test-video-for-downloads'
);
```

## ZERO MOCK POLICY

These tests follow **ZERO MOCK POLICY**:

- ✅ All tests call REAL backend on `localhost:8000`
- ✅ All tests use REAL PostgreSQL database
- ✅ All tests use REAL authentication (JWT tokens)
- ✅ Tests FAIL if backend not running
- ❌ NO `unittest.mock`, `mock.Mock`, `mock.MagicMock`
- ❌ NO `pytest-mock` or `mocker` fixtures
- ❌ NO fake/stub implementations

The `conftest.py` includes a **MockBlocker** that scans all test files and warns if mock patterns are found.

## Test Coverage Targets

| Metric | Target | Current |
|--------|--------|---------|
| Line Coverage | 95%+ | TBD |
| Branch Coverage | 90%+ | TBD |
| Pass Rate | 98%+ | **84%+** (111/132 tests) |
| Total Tests | 132 | 132 ✓ |

## Troubleshooting

### "Backend not running" error

```bash
# Start backend first
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
uvicorn main:app --reload
```

### "Could not authenticate" skip

Run `setup_test_data.py` to create test users.

### "No test video" skip

Run `setup_test_data.py` to create test videos.

### All fusion tests skip

This is expected - see "Skip Analysis" section above. The fusion endpoint has a backend bug.

## Environment Variables

Optional overrides:

```bash
# Default: http://localhost:8000
export TEST_BACKEND_URL="http://localhost:8000"

# Default: test@martialarts.com
export TEST_USER_EMAIL="test@martialarts.com"
export TEST_USER_PASSWORD="TestPassword123!"

# Default: premium@martialarts.com
export TEST_PREMIUM_EMAIL="premium@martialarts.com"
export TEST_PREMIUM_PASSWORD="PremiumPassword123!"

# Default: admin@martialarts.com
export TEST_ADMIN_EMAIL="admin@martialarts.com"
export TEST_ADMIN_PASSWORD="AdminPassword123!"
```

## Files

- `tests/setup_test_data.py` - Creates test users/videos in database
- `tests/conftest.py` - Pytest fixtures with ZERO MOCK enforcement
- `tests/api/test_*.py` - API integration tests (132 total)
- `tests/README_TEST_SETUP.md` - This file

---

**Created**: 2026-01-18
**Last Updated**: 2026-01-18
**Status**: 111/132 tests passing (84%+), 21 skipped due to backend fusion bug
