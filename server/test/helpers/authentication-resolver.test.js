const resolver = require('../../graph/resolvers/authentication')

describe('graph/resolvers/authentication login diagnostics', () => {
  beforeEach(() => {
    global.WIKI = {
      config: {
        sessionSecret: 'session-secret',
        devFlags: {
          ldapDebugEnabled: true,
          ldapDebugMode: 'MASKED',
          sqlLog: false
        },
        flags: {
          ldapdebug: true,
          sqllog: false
        }
      },
      models: {
        users: {
          login: jest.fn().mockRejectedValue(new Error('Invalid credentials'))
        },
        authentication: {
          getStrategy: jest.fn().mockResolvedValue({
            key: 'ldap-strategy',
            strategyKey: 'ldap'
          })
        }
      },
      logger: {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        debug: jest.fn()
      }
    }
  })

  afterEach(() => {
    delete global.WIKI
  })

  it('logs LDAP failure diagnostics and returns graphql error response', async () => {
    const context = { req: {} }
    const result = await resolver.AuthenticationMutation.login({}, {
      strategy: 'ldap-strategy',
      username: 'alice@example.org',
      password: 'bad-password'
    }, context)

    expect(result.responseResult.succeeded).toBe(false)
    expect(global.WIKI.models.authentication.getStrategy).toHaveBeenCalledWith('ldap-strategy')
    expect(global.WIKI.logger.warn).toHaveBeenCalled()
    expect(global.WIKI.logger.warn.mock.calls[0][0]).toContain('ldap.login.failure')
    expect(context.req.ldapDebug.traceId).toBeDefined()
  })
})
