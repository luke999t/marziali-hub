/// <reference types="cypress" />

// Custom commands
Cypress.Commands.add('login', (email: string, password: string) => {
  cy.request('POST', `${Cypress.env('apiUrl')}/auth/login`, {
    username: email,
    password: password
  }).then((response) => {
    window.localStorage.setItem('access_token', response.body.access_token)
    window.localStorage.setItem('user', JSON.stringify(response.body.user))
  })
})

Cypress.Commands.add('logout', () => {
  window.localStorage.removeItem('access_token')
  window.localStorage.removeItem('user')
})

// Type definitions
declare global {
  namespace Cypress {
    interface Chainable {
      login(email: string, password: string): Chainable<void>
      logout(): Chainable<void>
    }
  }
}

export {}
