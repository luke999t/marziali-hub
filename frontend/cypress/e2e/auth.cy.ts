describe('Authentication', () => {
  beforeEach(() => {
    cy.visit('/login')
  })

  it('should display login page', () => {
    cy.contains('Accedi al tuo account').should('be.visible')
    cy.get('input[type="email"]').should('be.visible')
    cy.get('input[type="password"]').should('be.visible')
  })

  it('should show error on invalid credentials', () => {
    cy.get('input[type="email"]').type('invalid@email.com')
    cy.get('input[type="password"]').type('wrongpassword')
    cy.get('button[type="submit"]').click()
    cy.contains('Credenziali non valide').should('be.visible')
  })

  it('should navigate to register page', () => {
    cy.contains('Registrati gratis').click()
    cy.url().should('include', '/register')
  })

  it('should login successfully with valid credentials', () => {
    // This test requires a test user in the database
    cy.intercept('POST', '**/auth/login', {
      statusCode: 200,
      body: {
        access_token: 'test-token',
        user: { id: '1', email: 'test@test.com', full_name: 'Test User' }
      }
    }).as('login')

    cy.get('input[type="email"]').type('test@test.com')
    cy.get('input[type="password"]').type('TestPassword123')
    cy.get('button[type="submit"]').click()

    cy.wait('@login')
    cy.url().should('eq', Cypress.config('baseUrl') + '/')
  })
})

describe('Registration', () => {
  beforeEach(() => {
    cy.visit('/register')
  })

  it('should display registration form', () => {
    cy.contains('Crea il tuo account').should('be.visible')
    cy.get('input[name="full_name"]').should('be.visible')
    cy.get('input[name="email"]').should('be.visible')
    cy.get('input[name="password"]').should('be.visible')
  })

  it('should validate password requirements', () => {
    cy.get('input[name="password"]').type('weak')
    cy.contains('Almeno 8 caratteri').should('be.visible')
    cy.contains('Una lettera maiuscola').should('be.visible')
  })

  it('should show password match error', () => {
    cy.get('input[name="password"]').type('StrongPass123')
    cy.get('input[name="confirmPassword"]').type('DifferentPass123')
    cy.contains('Le password non corrispondono').should('be.visible')
  })
})
