/* global WIKI */

// ------------------------------------
// LDAP Account
// ------------------------------------

const LdapStrategy = require('passport-ldapauth').Strategy
const fs = require('fs')
const _ = require('lodash')
const { logLdapEvent } = require('../../../helpers/ldap-debug')
const { isLdapDebugEnabled } = require('../../../helpers/dev-flags')

module.exports = {
  init (passport, conf) {
    passport.use(conf.key,
      new LdapStrategy({
        server: {
          url: conf.url,
          bindDn: conf.bindDn,
          bindCredentials: conf.bindCredentials,
          searchBase: conf.searchBase,
          searchFilter: conf.searchFilter,
          tlsOptions: getTlsOptions(conf),
          ...conf.mapGroups && {
            groupSearchBase: conf.groupSearchBase,
            groupSearchFilter: conf.groupSearchFilter,
            groupSearchScope: conf.groupSearchScope,
            groupDnProperty: conf.groupDnProperty,
            groupSearchAttributes: [conf.groupNameField]
          },
          includeRaw: true
        },
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
      }, async (req, profile, cb) => {
        const strategyKey = _.get(req, 'params.strategy', conf.key || 'unknown')
        const loginUsername = _.get(req, 'body.email', '')
        const searchFilter = conf.searchFilter
        const ldapUrl = conf.url

        logLdapEvent({
          req,
          strategyKey,
          stage: 'attempt',
          outcome: 'success',
          username: loginUsername,
          searchFilter,
          extra: {
            ldapUrl,
            tlsEnabled: conf.tlsEnabled === true
          }
        })

        try {
          const userId = _.get(profile, conf.mappingUID, null)
          logLdapEvent({
            req,
            strategyKey,
            stage: 'profile_received',
            outcome: 'success',
            username: loginUsername,
            extra: {
              hasUniqueId: !_.isNil(userId)
            }
          })
          if (!userId) {
            throw new Error('Invalid Unique ID field mapping!')
          }

          const user = await WIKI.models.users.processProfile({
            providerKey: req.params.strategy,
            profile: {
              id: userId,
              email: String(_.get(profile, conf.mappingEmail, '')).split(',')[0],
              displayName: _.get(profile, conf.mappingDisplayName, '???'),
              picture: _.get(profile, `_raw.${conf.mappingPicture}`, '')
            }
          })
          // map users LDAP groups to wiki groups with the same name, and remove any groups that don't match LDAP
          if (conf.mapGroups) {
            const ldapGroups = _.get(profile, '_groups')
            if (ldapGroups && _.isArray(ldapGroups)) {
              const groups = ldapGroups.map(g => g[conf.groupNameField])
              const currentGroups = (await user.$relatedQuery('groups').select('groups.id')).map(g => g.id)
              const expectedGroups = Object.values(WIKI.auth.groups).filter(g => groups.includes(g.name)).map(g => g.id)
              for (const groupId of _.difference(expectedGroups, currentGroups)) {
                await user.$relatedQuery('groups').relate(groupId)
              }
              for (const groupId of _.difference(currentGroups, expectedGroups)) {
                await user.$relatedQuery('groups').unrelate().where('groupId', groupId)
              }
              logLdapEvent({
                req,
                strategyKey,
                stage: 'group_mapping',
                outcome: 'success',
                username: loginUsername,
                extra: {
                  providerGroupCount: groups.length,
                  expectedGroupCount: expectedGroups.length,
                  currentGroupCount: currentGroups.length
                }
              })
            } else {
              logLdapEvent({
                req,
                strategyKey,
                stage: 'group_mapping',
                outcome: 'failure',
                level: 'warn',
                username: loginUsername,
                error: new Error('Group mapping enabled but LDAP groups payload is missing or invalid')
              })
            }
          }
          logLdapEvent({
            req,
            strategyKey,
            stage: 'success',
            outcome: 'success',
            username: loginUsername
          })
          cb(null, user)
        } catch (err) {
          logLdapEvent({
            req,
            strategyKey,
            stage: 'failure',
            outcome: 'failure',
            level: 'warn',
            username: loginUsername,
            error: err
          })
          cb(err, null)
        }
      }
      ))
  }
}

function getTlsOptions(conf) {
  if (!conf.tlsEnabled) {
    return {}
  }

  if (!conf.tlsCertPath) {
    return {
      rejectUnauthorized: conf.verifyTLSCertificate
    }
  }

  const caList = []
  if (conf.verifyTLSCertificate) {
    try {
      caList.push(fs.readFileSync(conf.tlsCertPath))
    } catch (err) {
      if (isLdapDebugEnabled()) {
        logLdapEvent({
          strategyKey: conf.key || 'ldap',
          stage: 'tls_config_error',
          outcome: 'failure',
          level: 'warn',
          error: err,
          extra: {
            tlsCertPath: conf.tlsCertPath
          }
        })
      }
      throw new Error(`Failed to read LDAP TLS certificate at path ${conf.tlsCertPath}: ${err.message}`)
    }
  }

  return {
    rejectUnauthorized: conf.verifyTLSCertificate,
    ca: caList
  }
}
