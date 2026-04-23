const { getDevFlags, normalizeLdapDebugMode } = require('../../helpers/dev-flags')

describe('helpers/dev-flags', () => {
  it('uses typed devFlags when present', () => {
    const flags = getDevFlags({
      devFlags: {
        ldapDebugEnabled: true,
        ldapDebugMode: 'VERBOSE',
        sqlLog: true
      },
      flags: {
        ldapdebug: false,
        sqllog: false
      }
    })

    expect(flags).toEqual({
      ldapDebugEnabled: true,
      ldapDebugMode: 'VERBOSE',
      sqlLog: true
    })
  })

  it('falls back to legacy flags', () => {
    const flags = getDevFlags({
      flags: {
        ldapdebug: true,
        sqllog: true
      }
    })

    expect(flags.ldapDebugEnabled).toBe(true)
    expect(flags.sqlLog).toBe(true)
    expect(flags.ldapDebugMode).toBe('MASKED')
  })

  it('normalizes invalid ldap debug modes to MASKED', () => {
    expect(normalizeLdapDebugMode('verbose')).toBe('VERBOSE')
    expect(normalizeLdapDebugMode('invalid')).toBe('MASKED')
    expect(normalizeLdapDebugMode(null)).toBe('MASKED')
  })
})
