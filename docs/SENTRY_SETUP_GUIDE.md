# 🔍 Sentry Error Tracking - Complete Setup Guide

## Overview
This guide covers the complete Sentry implementation for:
- ✅ Backend (FastAPI) - **COMPLETE**
- ✅ Frontend (Next.js) - **COMPLETE**
- ⏳ Mobile (React Native + Expo) - **READY TO INSTALL**

---

## 1. Backend Setup (FastAPI) ✅

### Files Created:
- `backend/core/sentry_config.py` - Sentry configuration module
- `backend/main.py` - FastAPI app with Sentry integration
- `backend/.env.example` - Environment variables template

### Installation:

```bash
cd backend
pip install sentry-sdk[fastapi]==1.38.0  # Already in requirements.txt
```

### Configuration:

1. **Get Sentry DSN:**
   - Go to https://sentry.io
   - Create a new project (Python/FastAPI)
   - Copy the DSN

2. **Create `.env` file:**
```bash
cp .env.example .env
```

3. **Update `.env` with your Sentry DSN:**
```env
SENTRY_DSN=https://your-key@o123456.ingest.sentry.io/7654321
ENVIRONMENT=production
RELEASE=v1.0.0
```

### Usage in Code:

```python
from core.sentry_config import (
    add_breadcrumb,
    capture_exception,
    capture_message,
    set_user_context,
    set_custom_context,
)

# Add breadcrumb
add_breadcrumb("User uploaded video", category="video", level="info")

# Set user context
set_user_context(user_id="123", email="user@example.com")

# Add custom context
set_custom_context("payment", {
    "amount": 50.00,
    "currency": "EUR",
    "method": "stripe"
})

# Capture exception manually
try:
    process_video()
except Exception as e:
    capture_exception(e, tags={"video_id": "abc123"})

# Capture message
capture_message("Payment processing started", level="info")
```

### Test Endpoint:

```bash
# In development mode, test Sentry:
curl http://localhost:8000/sentry-test
```

---

## 2. Frontend Setup (Next.js) ✅

### Files Created:
- `frontend/sentry.client.config.ts` - Client-side configuration
- `frontend/sentry.server.config.ts` - Server-side configuration
- `frontend/sentry.edge.config.ts` - Edge runtime configuration
- `frontend/.env.example` - Environment variables template

### Installation:

```bash
cd frontend
npm install @sentry/nextjs@^8.0.0  # Added to package.json
```

### Configuration:

1. **Get Sentry DSN:**
   - Go to https://sentry.io
   - Create a new project (JavaScript/Next.js)
   - Copy the DSN

2. **Create `.env.local` file:**
```bash
cp .env.example .env.local
```

3. **Update `.env.local`:**
```env
NEXT_PUBLIC_SENTRY_DSN=https://your-key@o123456.ingest.sentry.io/7654321
NEXT_PUBLIC_ENVIRONMENT=production
NEXT_PUBLIC_RELEASE=v1.0.0
```

### Update next.config.js:

The Sentry webpack plugin is configured automatically. Make sure your `next.config.js` exports the withPWA wrapped config (already done).

### Usage in Code:

```typescript
import * as Sentry from '@sentry/nextjs';

// Set user context
Sentry.setUser({ id: '123', email: 'user@example.com' });

// Add breadcrumb
Sentry.addBreadcrumb({
  category: 'navigation',
  message: 'User navigated to /courses',
  level: 'info',
});

// Capture exception
try {
  await fetchData();
} catch (error) {
  Sentry.captureException(error, {
    tags: { section: 'courses' },
    extra: { userId: '123' }
  });
}

// Capture message
Sentry.captureMessage('Important event occurred', 'info');
```

### Error Boundary (React):

```typescript
'use client';

import { useEffect } from 'react';
import * as Sentry from '@sentry/nextjs';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    Sentry.captureException(error);
  }, [error]);

  return (
    <div>
      <h2>Something went wrong!</h2>
      <button onClick={reset}>Try again</button>
    </div>
  );
}
```

---

## 3. Mobile Setup (React Native + Expo) ⏳

### Installation:

```bash
cd mobile  # When mobile directory exists

# Install Sentry for React Native with Expo
npx expo install @sentry/react-native

# Install native dependencies
npx expo install expo-dev-client
```

### Configuration:

1. **Create `sentry.config.ts`:**

```typescript
import * as Sentry from '@sentry/react-native';

Sentry.init({
  dsn: 'https://your-key@o123456.ingest.sentry.io/7654321',

  // Environment
  environment: __DEV__ ? 'development' : 'production',
  release: 'media-center-mobile@1.0.0',

  // Performance Monitoring
  tracesSampleRate: __DEV__ ? 1.0 : 0.1,

  // Don't send PII
  sendDefaultPii: false,

  // Enable native crash reporting
  enableNative: true,
  enableNativeNagger: false,

  // Ignore errors
  ignoreErrors: [
    'Network request failed',
    'Timeout',
  ],
});
```

2. **Wrap App with Sentry in `App.tsx`:**

```typescript
import * as Sentry from '@sentry/react-native';
import './sentry.config';

function App() {
  return <YourApp />;
}

export default Sentry.wrap(App);
```

3. **Create Error Boundary:**

```typescript
import React from 'react';
import * as Sentry from '@sentry/react-native';
import { View, Text, Button } from 'react-native';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    Sentry.captureException(error, {
      contexts: { react: { componentStack: errorInfo.componentStack } }
    });
  }

  render() {
    if (this.state.hasError) {
      return (
        <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
          <Text>Qualcosa è andato storto</Text>
          <Button
            title="Riprova"
            onPress={() => this.setState({ hasError: false })}
          />
        </View>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
```

### Usage in React Native:

```typescript
import * as Sentry from '@sentry/react-native';

// Set user
Sentry.setUser({ id: '123', email: 'user@example.com' });

// Add breadcrumb
Sentry.addBreadcrumb({
  category: 'navigation',
  message: 'User opened chat screen',
  level: 'info',
});

// Capture exception
try {
  await fetchData();
} catch (error) {
  Sentry.captureException(error, {
    tags: { screen: 'ChatScreen' }
  });
}

// Capture message
Sentry.captureMessage('Video playback started', 'info');
```

### Expo Configuration (`app.json`):

```json
{
  "expo": {
    "plugins": [
      [
        "@sentry/react-native/expo",
        {
          "organization": "your-org",
          "project": "media-center-mobile"
        }
      ]
    ],
    "hooks": {
      "postPublish": [
        {
          "file": "sentry-expo/upload-sourcemaps",
          "config": {
            "organization": "your-org",
            "project": "media-center-mobile"
          }
        }
      ]
    }
  }
}
```

---

## 4. Testing Sentry

### Backend Test:
```bash
curl http://localhost:8000/sentry-test
# Check Sentry dashboard for the test error
```

### Frontend Test:
Add a test button in development:
```typescript
<button onClick={() => { throw new Error('Sentry test error') }}>
  Test Sentry
</button>
```

### Mobile Test:
```typescript
<Button
  title="Test Sentry"
  onPress={() => {
    throw new Error('Sentry test error');
  }}
/>
```

---

## 5. Best Practices

### DO:
✅ Set user context after login
✅ Add breadcrumbs for important actions
✅ Use custom contexts for domain-specific data
✅ Filter sensitive data (passwords, tokens)
✅ Set appropriate sample rates in production
✅ Use tags for filtering (environment, version, user_tier)

### DON'T:
❌ Send PII (personally identifiable information)
❌ Capture expected errors (validation, auth failures)
❌ Over-sample in production (costs money)
❌ Ignore Sentry alerts
❌ Leave test errors in production

---

## 6. Monitoring Dashboard

### Key Metrics to Monitor:
- **Error Rate**: Errors per minute/hour
- **Users Affected**: Number of unique users experiencing errors
- **Release Health**: Crash-free sessions percentage
- **Performance**: Transaction duration, throughput

### Alerts to Setup:
1. **Critical Errors**: Immediate notification for 500 errors
2. **Error Spike**: Alert when error rate increases >50%
3. **New Issues**: Notify on first occurrence of new error types
4. **Performance Degradation**: Alert when p95 latency >2s

---

## 7. Cost Optimization

### Sentry Pricing (as of 2025):
- **Developer Plan**: Free - 5K errors/month
- **Team Plan**: $26/month - 50K errors/month
- **Business Plan**: $80/month - 100K errors/month

### Tips to Reduce Costs:
1. Filter noisy errors with `ignoreErrors`
2. Use `beforeSend` to filter events
3. Sample performance traces (10% in production)
4. Don't capture in development (or use local Sentry instance)
5. Set `maxBreadcrumbs` to reasonable value (50)

---

## 8. Next Steps

After Sentry is fully configured:

1. **Setup Alerts** in Sentry dashboard
2. **Configure Integrations**:
   - Slack notifications
   - GitHub issue creation
   - PagerDuty for critical errors
3. **Create Release Tracking**:
   ```bash
   sentry-cli releases new v1.0.0
   sentry-cli releases set-commits v1.0.0 --auto
   sentry-cli releases finalize v1.0.0
   ```
4. **Monitor Release Health** to track crash-free sessions

---

## Status

| Component | Status | Files |
|-----------|--------|-------|
| Backend | ✅ Complete | `core/sentry_config.py`, `main.py` |
| Frontend | ✅ Complete | `sentry.*.config.ts`, package.json |
| Mobile | ⏳ Ready to install | Guide above (when mobile/ exists) |

**Total Implementation Time**: ~2 hours
**Estimated Monthly Cost**: $26-80 (Team/Business plan)

---

## Support

- **Sentry Docs**: https://docs.sentry.io
- **Next.js Integration**: https://docs.sentry.io/platforms/javascript/guides/nextjs/
- **React Native Integration**: https://docs.sentry.io/platforms/react-native/
- **FastAPI Integration**: https://docs.sentry.io/platforms/python/guides/fastapi/
