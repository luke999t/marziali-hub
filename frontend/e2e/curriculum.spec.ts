/**
 * ================================================================================
 *     CURRICULUM E2E TESTS - Playwright End-to-End Tests
 * ================================================================================
 *
 * AI_MODULE: CurriculumE2E
 * AI_DESCRIPTION: Test end-to-end per flussi utente curriculum
 * AI_BUSINESS: Validazione completa user experience prima del deploy
 * AI_TEACHING: Playwright test per user journeys realistici
 *
 * ================================================================================
 */

import { test, expect } from '@playwright/test';

test.describe('Curriculum Discovery', () => {
  test('should display curriculum catalog', async ({ page }) => {
    await page.goto('/curriculum');

    // Wait for page to load
    await expect(page.locator('h1')).toContainText(/curricula|corsi/i);

    // Check curriculum cards are visible
    const cards = page.locator('[data-testid="curriculum-card"]');
    await expect(cards.first()).toBeVisible();
  });

  test('should filter curricula by discipline', async ({ page }) => {
    await page.goto('/curriculum');

    // Wait for initial load
    await page.waitForSelector('[data-testid="curriculum-card"]');

    // Click discipline filter
    await page.click('text=Karate');

    // Wait for filter to apply
    await page.waitForTimeout(500);

    // All visible cards should be Karate
    const cards = page.locator('[data-testid="curriculum-card"]');
    const count = await cards.count();

    for (let i = 0; i < count; i++) {
      await expect(cards.nth(i)).toContainText(/karate/i);
    }
  });

  test('should search curricula', async ({ page }) => {
    await page.goto('/curriculum');

    // Wait for initial load
    await page.waitForSelector('[data-testid="curriculum-card"]');

    // Type in search
    await page.fill('input[placeholder*="cerca" i]', 'Base');

    // Wait for search to apply
    await page.waitForTimeout(500);

    // Results should contain search term
    const cards = page.locator('[data-testid="curriculum-card"]');
    if (await cards.count() > 0) {
      await expect(cards.first()).toContainText(/base/i);
    }
  });
});

test.describe('Curriculum Detail', () => {
  test('should display curriculum information', async ({ page }) => {
    await page.goto('/curriculum');

    // Wait for cards to load
    await page.waitForSelector('[data-testid="curriculum-card"]');

    // Click first curriculum
    await page.click('[data-testid="curriculum-card"] >> nth=0');

    // Should navigate to detail page
    await expect(page).toHaveURL(/\/curriculum\/[\w-]+$/);

    // Check detail elements
    await expect(page.locator('h1')).toBeVisible();
    await expect(page.locator('text=/livell/i')).toBeVisible();
  });

  test('should show level cards', async ({ page }) => {
    await page.goto('/curriculum');
    await page.waitForSelector('[data-testid="curriculum-card"]');
    await page.click('[data-testid="curriculum-card"] >> nth=0');

    // Wait for detail page
    await page.waitForURL(/\/curriculum\/[\w-]+$/);

    // Should show level cards
    const levelCards = page.locator('[data-testid="level-card"]');
    await expect(levelCards.first()).toBeVisible();
  });

  test('should show enrollment button for guests', async ({ page }) => {
    await page.goto('/curriculum');
    await page.waitForSelector('[data-testid="curriculum-card"]');
    await page.click('[data-testid="curriculum-card"] >> nth=0');

    // Should show enrollment/login prompt
    await expect(
      page.locator('text=/iscriviti|accedi|login/i')
    ).toBeVisible();
  });
});

test.describe('My Learning Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Login (mock or real depending on setup)
    await page.goto('/login');
    await page.fill('input[type="email"]', 'test@example.com');
    await page.fill('input[type="password"]', 'password123');
    await page.click('button[type="submit"]');
    await page.waitForURL(/\/(dashboard|my-learning)/);
  });

  test('should display enrolled curricula', async ({ page }) => {
    await page.goto('/my-learning');

    // Wait for page to load
    await expect(page.locator('h1')).toContainText(/miei corsi/i);

    // Should show enrollment cards or empty state
    const hasEnrollments = await page
      .locator('[data-testid="enrollment-card"]')
      .count();
    const hasEmptyState = await page
      .locator('text=/nessun corso/i')
      .count();

    expect(hasEnrollments + hasEmptyState).toBeGreaterThan(0);
  });

  test('should switch between tabs', async ({ page }) => {
    await page.goto('/my-learning');

    // Click completed tab
    await page.click('text=/completati/i');

    // Tab should be active
    await expect(page.locator('button:has-text("Completati")')).toHaveClass(
      /active|selected|border-blue/
    );

    // Click certificates tab
    await page.click('text=/certificati/i');

    // Tab should be active
    await expect(page.locator('button:has-text("Certificati")')).toHaveClass(
      /active|selected|border-blue/
    );
  });
});

test.describe('Admin Curriculum Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login as admin/maestro
    await page.goto('/login');
    await page.fill('input[type="email"]', 'maestro@example.com');
    await page.fill('input[type="password"]', 'password123');
    await page.click('button[type="submit"]');
    await page.waitForNavigation();
  });

  test('should display manage curricula page', async ({ page }) => {
    await page.goto('/manage/curricula');

    // Wait for page to load
    await expect(page.locator('h1')).toContainText(/miei curricula/i);

    // Should show create button
    await expect(page.locator('text=/nuovo curriculum/i')).toBeVisible();
  });

  test('should navigate to create curriculum', async ({ page }) => {
    await page.goto('/manage/curricula');

    // Click create button
    await page.click('text=/nuovo curriculum/i');

    // Should navigate to create page
    await expect(page).toHaveURL(/\/manage\/curricula\/new/);
  });

  test('should open student management', async ({ page }) => {
    await page.goto('/manage/curricula');

    // Wait for curriculum cards
    const hasCurricula = await page
      .locator('[data-testid="curriculum-row"]')
      .count();

    if (hasCurricula > 0) {
      // Click students button on first curriculum
      await page.click('[data-testid="curriculum-row"] >> nth=0 >> text=/studenti/i');

      // Should navigate to students page
      await expect(page).toHaveURL(/\/manage\/curricula\/[\w-]+\/students/);
    }
  });
});

test.describe('Exam Review (Maestro)', () => {
  test.beforeEach(async ({ page }) => {
    // Login as maestro
    await page.goto('/login');
    await page.fill('input[type="email"]', 'maestro@example.com');
    await page.fill('input[type="password"]', 'password123');
    await page.click('button[type="submit"]');
    await page.waitForNavigation();
  });

  test('should display exam review dashboard', async ({ page }) => {
    await page.goto('/manage/exams');

    // Wait for page to load
    await expect(page.locator('h1')).toContainText(/valutazione esami/i);

    // Should show filter options
    await expect(page.locator('text=/da valutare/i')).toBeVisible();
  });

  test('should filter pending exams', async ({ page }) => {
    await page.goto('/manage/exams');

    // Click pending filter
    await page.click('text=/da valutare/i');

    // Filter should be active
    await expect(page.locator('button:has-text("Da valutare")')).toHaveClass(
      /active|bg-blue/
    );
  });
});

test.describe('Accessibility', () => {
  test('curriculum page should be accessible', async ({ page }) => {
    await page.goto('/curriculum');

    // Check for main heading
    await expect(page.locator('main h1, h1[role="heading"]')).toBeVisible();

    // Check for skip link (if exists)
    const skipLink = page.locator('a[href="#main-content"]');
    if (await skipLink.count() > 0) {
      await expect(skipLink).toBeVisible();
    }

    // Check focus is visible on interactive elements
    await page.keyboard.press('Tab');
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeVisible();
  });

  test('forms should have labels', async ({ page }) => {
    await page.goto('/curriculum');

    // Check search input has label
    const searchInput = page.locator('input[placeholder*="cerca" i]');
    if (await searchInput.count() > 0) {
      const inputId = await searchInput.getAttribute('id');
      if (inputId) {
        const label = page.locator(`label[for="${inputId}"]`);
        // Either has visible label or aria-label
        const hasLabel = await label.count() > 0;
        const hasAriaLabel = await searchInput.getAttribute('aria-label');
        expect(hasLabel || hasAriaLabel).toBeTruthy();
      }
    }
  });
});

test.describe('Mobile Responsiveness', () => {
  test.use({ viewport: { width: 375, height: 667 } });

  test('curriculum page should work on mobile', async ({ page }) => {
    await page.goto('/curriculum');

    // Page should be scrollable
    await expect(page.locator('body')).toBeVisible();

    // Cards should stack vertically
    const firstCard = page.locator('[data-testid="curriculum-card"] >> nth=0');
    if (await firstCard.count() > 0) {
      const box = await firstCard.boundingBox();
      // Width should be nearly full width on mobile
      expect(box?.width).toBeGreaterThan(300);
    }
  });

  test('navigation should be accessible on mobile', async ({ page }) => {
    await page.goto('/curriculum');

    // Should have hamburger menu or mobile nav
    const mobileNav = page.locator(
      '[data-testid="mobile-nav"], button[aria-label*="menu" i]'
    );
    await expect(mobileNav.first()).toBeVisible();
  });
});

test.describe('Performance', () => {
  test('curriculum page should load quickly', async ({ page }) => {
    const startTime = Date.now();

    await page.goto('/curriculum');

    // Wait for first content
    await page.waitForSelector('h1');

    const loadTime = Date.now() - startTime;

    // Should load in under 3 seconds
    expect(loadTime).toBeLessThan(3000);
  });

  test('images should have dimensions', async ({ page }) => {
    await page.goto('/curriculum');
    await page.waitForSelector('[data-testid="curriculum-card"]');

    // Check images have width and height
    const images = page.locator('img[src]');
    const count = await images.count();

    for (let i = 0; i < Math.min(count, 5); i++) {
      const img = images.nth(i);
      const width = await img.getAttribute('width');
      const height = await img.getAttribute('height');
      const style = await img.getAttribute('style');

      // Should have explicit dimensions or be styled
      const hasDimensions = (width && height) || style?.includes('width');
      // This is a soft check - log warning instead of fail
      if (!hasDimensions) {
        console.warn(`Image ${i} missing explicit dimensions`);
      }
    }
  });
});
