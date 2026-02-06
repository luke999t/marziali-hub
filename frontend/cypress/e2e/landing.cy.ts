describe('Landing Page', () => {
  beforeEach(() => {
    cy.visit('/landing')
  })

  it('should display hero section', () => {
    cy.contains('Impara le Arti Marziali').should('be.visible')
    cy.contains('Inizia Gratis').should('be.visible')
  })

  it('should display features section', () => {
    cy.contains('Video HD').should('be.visible')
    cy.contains('Community').should('be.visible')
    cy.contains('AI Coach').should('be.visible')
  })

  it('should display pricing section', () => {
    cy.get('#pricing').scrollIntoView()
    cy.contains('Free').should('be.visible')
    cy.contains('Premium').should('be.visible')
    cy.contains('Maestro').should('be.visible')
  })

  it('should navigate to login', () => {
    cy.contains('Accedi').click()
    cy.url().should('include', '/login')
  })

  it('should navigate to register', () => {
    cy.contains('Registrati').first().click()
    cy.url().should('include', '/register')
  })

  it('should display testimonials', () => {
    cy.get('#testimonials').scrollIntoView()
    cy.contains('Cosa dicono i nostri utenti').should('be.visible')
  })

  it('should have responsive header', () => {
    cy.viewport('iphone-x')
    cy.get('header').should('be.visible')
  })
})
