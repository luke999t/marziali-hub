# Media Center Arti Marziali - API Documentation

This directory contains complete API documentation and SDK generation tools.

## Contents

```
docs/
├── API_REFERENCE.md          # Main API reference
├── README.md                 # This file
├── generate_docs.py          # Documentation generator script
├── api/                      # Per-router documentation
│   ├── auth.md
│   ├── users.md
│   ├── videos.md
│   └── ... (43 router docs)
└── openapi/
    ├── openapi.json          # OpenAPI 3.1 specification
    └── openapi.yaml          # YAML version
```

## Quick Start

### View API Documentation

1. **Swagger UI** (interactive): http://localhost:8000/docs
2. **ReDoc** (readable): http://localhost:8000/redoc
3. **Markdown docs**: See [API_REFERENCE.md](API_REFERENCE.md)

### Export OpenAPI Spec

```bash
# With backend running on localhost:8000
curl http://localhost:8000/openapi.json > docs/openapi/openapi.json

# Or use the Python script
python backend/scripts/export_openapi.py
```

## SDK Generation

### Prerequisites

```bash
# Node.js (for TypeScript SDK)
npm --version

# Java (for Dart SDK via openapi-generator)
java --version
```

### Regenerate TypeScript SDK (Frontend)

```bash
cd frontend

# Install generator if needed
npm install -g openapi-typescript-codegen

# Generate SDK
npx openapi-typescript-codegen \
  --input ../docs/openapi/openapi.json \
  --output src/api/generated \
  --client axios

# Verify
ls src/api/generated/
```

**Output structure:**
```
frontend/src/api/
├── generated/           # Auto-generated (339 files)
│   ├── core/           # API core utilities
│   ├── models/         # TypeScript interfaces
│   └── services/       # API service classes
├── client.ts           # Auth wrapper
└── index.ts            # Main export
```

**Usage:**
```typescript
import { apiClient, AuthService, VideosService } from '@/api';

// Login
const auth = await AuthService.loginApiV1AuthLoginPost({
  email: 'user@example.com',
  password: 'password123'
});
apiClient.setTokens(auth);

// Make authenticated requests
const videos = await VideosService.listVideosApiV1VideosGet();
```

### Regenerate Dart SDK (Flutter)

```bash
cd flutter_app

# Install OpenAPI Generator
npm install -g @openapitools/openapi-generator-cli

# Generate SDK
npx @openapitools/openapi-generator-cli generate \
  -i ../docs/openapi/openapi.json \
  -g dart-dio \
  -o lib/api/generated \
  --additional-properties=pubName=media_center_api,pubVersion=1.0.0

# Get dependencies
cd lib/api/generated && dart pub get
```

**Output structure:**
```
flutter_app/lib/api/
├── generated/           # Auto-generated (1014 files)
│   ├── lib/            # Dart library
│   ├── doc/            # API documentation
│   └── pubspec.yaml    # Package config
└── client.dart         # Auth wrapper
```

**Usage:**
```dart
import 'package:flutter_app/api/client.dart';

// Initialize
initializeApiClient(
  baseUrl: 'http://localhost:8000',
  onUnauthorized: () => navigateToLogin(),
);

// Login
final auth = await apiClient.auth.loginApiV1AuthLoginPost(
  userLoginRequest: UserLoginRequest(
    email: 'user@example.com',
    password: 'password',
  ),
);
await apiClient.setTokens(auth.accessToken!, auth.refreshToken!);

// Make authenticated requests
final videos = await apiClient.videos.listVideosApiV1VideosGet();
```

## Regenerate Documentation

```bash
# Ensure backend is running
curl http://localhost:8000/health

# Download latest OpenAPI spec
curl http://localhost:8000/openapi.json > docs/openapi/openapi.json

# Generate markdown docs
python docs/generate_docs.py
```

## API Statistics

| Metric | Value |
|--------|-------|
| Total Endpoints | 411 |
| API Tags/Routers | 43 |
| TypeScript SDK Files | 339 |
| Dart SDK Files | 1014 |
| Documentation Files | 44 |

## Validation

### Validate OpenAPI Spec

```bash
# Install validator
npm install -g @apidevtools/swagger-cli

# Validate
npx @apidevtools/swagger-cli validate docs/openapi/openapi.json
```

### Test TypeScript SDK Compilation

```bash
cd frontend
npm run type-check
# or
npx tsc --noEmit
```

### Test Dart SDK Compilation

```bash
cd flutter_app/lib/api/generated
dart pub get
dart analyze
```

## Updating After API Changes

When backend API changes:

1. **Export new spec:**
   ```bash
   curl http://localhost:8000/openapi.json > docs/openapi/openapi.json
   ```

2. **Regenerate docs:**
   ```bash
   python docs/generate_docs.py
   ```

3. **Regenerate TypeScript SDK:**
   ```bash
   cd frontend
   npx openapi-typescript-codegen --input ../docs/openapi/openapi.json --output src/api/generated --client axios
   ```

4. **Regenerate Dart SDK:**
   ```bash
   cd flutter_app
   npx @openapitools/openapi-generator-cli generate -i ../docs/openapi/openapi.json -g dart-dio -o lib/api/generated
   ```

5. **Test both SDKs compile correctly**

## Troubleshooting

### TypeScript SDK Issues

**"Cannot find module" errors:**
```bash
cd frontend
rm -rf src/api/generated
# Regenerate SDK
npm run generate-api  # if script exists, or use npx command above
```

### Dart SDK Issues

**"Package not found" errors:**
```bash
cd flutter_app/lib/api/generated
dart pub get
```

**Analysis errors:**
The generated Dart code may have lint warnings. These are usually safe to ignore for generated code.

## Contributing

1. Backend API changes should update OpenAPI annotations
2. Run regeneration scripts after API changes
3. Test SDK compilation before committing
4. Update documentation if adding new routers

---

*Generated: 2026-01-28*
*OpenAPI Version: 3.1.0*
