# US-004: Frontend Auth Flow Fix

## Overview
Fix login/logout navigation in Next.js frontend.

## Current Issues
- Login doesn't redirect to dashboard
- Logout doesn't clear state properly
- Protected routes may not work

## Tasks

### 1. AuthContext.tsx
- [ ] Check token storage (localStorage vs cookies)
- [ ] Verify login() sets token correctly
- [ ] Verify logout() clears all auth state
- [ ] Add loading state during auth check

### 2. Login Page
- [ ] On success → redirect to /dashboard
- [ ] Show error message on failure
- [ ] Disable button during submission

### 3. Middleware
- [ ] Check token on protected routes
- [ ] Redirect to /login if not authenticated
- [ ] Allow public routes (/login, /register, /)

### 4. Testing
- [ ] Manual test: login → dashboard
- [ ] Manual test: logout → home
- [ ] Manual test: direct URL to protected page

## Files to Modify

```
frontend/src/contexts/AuthContext.tsx
frontend/src/app/(auth)/login/page.tsx
frontend/src/middleware.ts
```

## Acceptance Criteria

- [ ] Login redirects to dashboard on success
- [ ] Logout clears token and redirects to home
- [ ] Protected routes redirect to login if not authenticated
- [ ] No console errors on auth pages

## Estimated Effort: 3 hours
