describe('Admin Dashboard', () => {
  beforeEach(() => {
    // Mock admin login
    cy.intercept('GET', '**/admin/stats', {
      statusCode: 200,
      body: {
        totalUsers: 1500,
        activeUsers: 320,
        totalVideos: 450,
        pendingModeration: 12,
        totalRevenue: 25000,
        monthlyRevenue: 3500,
        activeSubscriptions: 850,
        reportedContent: 3
      }
    }).as('getStats')

    window.localStorage.setItem('access_token', 'admin-token')
    cy.visit('/admin')
  })

  it('should display admin dashboard', () => {
    cy.contains('Admin Dashboard').should('be.visible')
  })

  it('should show statistics cards', () => {
    cy.contains('Total Users').should('be.visible')
    cy.contains('Monthly Revenue').should('be.visible')
    cy.contains('Pending Moderation').should('be.visible')
  })

  it('should navigate to user management', () => {
    cy.contains('User Management').click()
    cy.url().should('include', '/admin/users')
  })

  it('should navigate to moderation', () => {
    cy.contains('Content Moderation').click()
    cy.url().should('include', '/admin/moderation')
  })

  it('should navigate to analytics', () => {
    cy.contains('Analytics').click()
    cy.url().should('include', '/admin/analytics')
  })
})

describe('Admin User Management', () => {
  beforeEach(() => {
    cy.intercept('GET', '**/admin/users*', {
      statusCode: 200,
      body: {
        users: [
          { id: '1', email: 'user1@test.com', full_name: 'User One', role: 'user', is_active: true, created_at: '2024-01-01' },
          { id: '2', email: 'maestro@test.com', full_name: 'Maestro Test', role: 'maestro', is_active: true, created_at: '2024-01-15' }
        ],
        total_pages: 1
      }
    }).as('getUsers')

    window.localStorage.setItem('access_token', 'admin-token')
    cy.visit('/admin/users')
  })

  it('should display users table', () => {
    cy.wait('@getUsers')
    cy.contains('User Management').should('be.visible')
    cy.contains('User One').should('be.visible')
    cy.contains('Maestro Test').should('be.visible')
  })

  it('should filter by role', () => {
    cy.get('select').select('maestro')
    cy.wait('@getUsers')
  })

  it('should search users', () => {
    cy.get('input[placeholder="Search users..."]').type('maestro')
  })
})

describe('Admin Analytics', () => {
  beforeEach(() => {
    cy.intercept('GET', '**/admin/analytics*', {
      statusCode: 200,
      body: {
        overview: {
          total_views: 125000,
          total_watch_time: 45000,
          total_revenue: 8500,
          new_users: 340,
          active_subscribers: 1250
        },
        daily_views: [],
        top_videos: [],
        revenue_by_type: []
      }
    }).as('getAnalytics')

    window.localStorage.setItem('access_token', 'admin-token')
    cy.visit('/admin/analytics')
  })

  it('should display analytics dashboard', () => {
    cy.contains('Analytics').should('be.visible')
    cy.contains('Total Views').should('be.visible')
    cy.contains('Revenue').should('be.visible')
  })

  it('should change time period', () => {
    cy.get('select').select('7d')
    cy.wait('@getAnalytics')
  })
})
