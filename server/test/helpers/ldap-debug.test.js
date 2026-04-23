const {
  createTraceId,
  setTraceId,
  getTraceId,
  logLdapEvent,
  getUsernameToken
} = require('../../helpers/ldap-debug')

describe('helpers/ldap-debug', () => {
  beforeEach(() => {
    global.WIKI = {
      config: {
        sessionSecret: 'test-secret',
        devFlags: {
          ldapDebugEnabled: true,
          ldapDebugMode: 'MASKED',
          sqlLog: false
        }
      },
      logger: {
        info: jest.fn(),
        warn: jest.fn()
      }
    }
  })

  afterEach(() => {
    delete global.WIKI
  })

  it('creates and propagates trace IDs', () => {
    const req = {}
    const traceId = createTraceId()
    setTraceId(req, traceId)
    expect(getTraceId(req)).toBe(traceId)
    expect(traceId).toHaveLength(16)
  })

  it('logs masked payloads with username token', () => {
    const req = {}
    setTraceId(req, 'trace1234')

    logLdapEvent({
      req,
      strategyKey: 'ldap-1',
      stage: 'attempt',
      outcome: 'success',
      username: 'alice@example.org',
      searchFilter: '(uid={{username}})'
    })

    expect(global.WIKI.logger.info).toHaveBeenCalledTimes(1)
    const msg = global.WIKI.logger.info.mock.calls[0][0]
    expect(msg).toContain('[LDAP DEBUG]')
    expect(msg).toContain('"traceId":"trace1234"')
    expect(msg).toContain('"stage":"attempt"')
    expect(msg).toContain('"usernameToken":"')
    expect(msg).not.toContain('alice@example.org')
    expect(msg).toContain('"searchFilter":"[REDACTED]"')
  })

  it('logs verbose payloads with raw values', () => {
    global.WIKI.config.devFlags.ldapDebugMode = 'VERBOSE'
    const req = {}
    setTraceId(req, 'trace9999')

    logLdapEvent({
      req,
      strategyKey: 'ldap-1',
      stage: 'failure',
      outcome: 'failure',
      level: 'warn',
      username: 'bob@example.org',
      searchFilter: '(uid={{username}})',
      error: new Error('Bind failed')
    })

    expect(global.WIKI.logger.warn).toHaveBeenCalledTimes(1)
    const msg = global.WIKI.logger.warn.mock.calls[0][0]
    expect(msg).toContain('"username":"bob@example.org"')
    expect(msg).toContain('"searchFilter":"(uid={{username}})"')
    expect(msg).toContain('"errorMessage":"Bind failed"')
  })

  it('generates stable username tokens', () => {
    const a = getUsernameToken('alice@example.org')
    const b = getUsernameToken('alice@example.org')
    const c = getUsernameToken('other@example.org')
    expect(a).toBe(b)
    expect(a).not.toBe(c)
  })
})
