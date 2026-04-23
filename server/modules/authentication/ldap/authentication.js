/* global WIKI */

// ------------------------------------
// LDAP Account
// ------------------------------------

const LdapStrategy = require('passport-ldapauth').Strategy
const ldap = require('ldapjs')
const fs = require('fs')
const _ = require('lodash')
const { logLdapEvent } = require('../../../helpers/ldap-debug')
const { isLdapDebugEnabled } = require('../../../helpers/dev-flags')

module.exports = {
  async preflight (conf) {
    if (!isLdapDebugEnabled()) {
      return
    }

    const strategyKey = conf.key || 'ldap'
    const configValidation = validatePreflightConfig(conf)
    if (!configValidation.valid) {
      logLdapEvent({
        strategyKey,
        stage: 'preflight_config_validation',
        outcome: 'failure',
        level: 'warn',
        error: new Error('LDAP preflight configuration is incomplete or invalid'),
        extra: {
          phase: 'startup_preflight_config_validation',
          missingFields: configValidation.missingFields,
          invalidFields: configValidation.invalidFields
        }
      })
      return
    }
    logLdapEvent({
      strategyKey,
      stage: 'preflight_config_validation',
      outcome: 'success',
      extra: {
        phase: 'startup_preflight_config_validation',
        ldapUrlDefined: true,
        bindDnDefined: true,
        bindCredentialsDefined: true,
        searchBaseDefined: true,
        searchFilterDefined: true,
        tlsEnabled: conf.tlsEnabled === true,
        tlsCertPathDefined: !_.isEmpty(conf.tlsCertPath),
        mapGroups: conf.mapGroups === true,
        groupSearchScope: normalizeSearchScope(conf.groupSearchScope)
      }
    })

    const tlsOptions = getTlsOptions(conf)
    let client = null
    let userSearchFilter = null
    let userDnCandidate = null
    let userEntryCandidate = null

    try {
      client = ldap.createClient({
        url: conf.url,
        timeout: 8000,
        connectTimeout: 8000,
        idleTimeout: 8000,
        tlsOptions
      })

      await bindClient(client, conf.bindDn, conf.bindCredentials)
      logLdapEvent({
        strategyKey,
        stage: 'preflight_bind',
        outcome: 'success',
        extra: {
          phase: 'startup_preflight_bind',
          ldapUrl: conf.url,
          tlsEnabled: conf.tlsEnabled === true
        }
      })
    } catch (err) {
      logLdapEvent({
        strategyKey,
        stage: 'preflight_bind',
        outcome: 'failure',
        level: 'warn',
        error: err,
        extra: {
          phase: 'startup_preflight_bind'
        }
      })
      safeUnbind(client)
      return
    }

    try {
      userSearchFilter = buildPreflightUserSearchFilter(conf.searchFilter)
      const userSearchResult = await searchEntries(client, conf.searchBase, userSearchFilter, {
        scope: 'sub',
        sizeLimit: 2,
        timeLimit: 6,
        attributes: buildPreflightUserAttributes(conf)
      })
      userEntryCandidate = _.first(userSearchResult.entries) || null
      userDnCandidate = _.get(userEntryCandidate, 'dn', null)
      logLdapEvent({
        strategyKey,
        stage: 'preflight_user_search',
        outcome: 'success',
        searchFilter: userSearchFilter,
        extra: {
          phase: 'startup_preflight_user_search',
          resultCount: userSearchResult.count,
          hasCandidateDn: !_.isNil(userDnCandidate)
        }
      })

      const mappingValidation = validateUserMappings(conf, userEntryCandidate)
      if (!mappingValidation.valid) {
        logLdapEvent({
          strategyKey,
          stage: 'preflight_mapping_validation',
          outcome: 'failure',
          level: 'warn',
          error: new Error('LDAP preflight mapping validation failed'),
          extra: {
            phase: 'startup_preflight_mapping_validation',
            mappingIssues: mappingValidation.issues,
            userEntryFound: mappingValidation.userEntryFound
          }
        })
        safeUnbind(client)
        return
      }
      logLdapEvent({
        strategyKey,
        stage: 'preflight_mapping_validation',
        outcome: 'success',
        extra: {
          phase: 'startup_preflight_mapping_validation',
          userEntryFound: mappingValidation.userEntryFound
        }
      })
    } catch (err) {
      logLdapEvent({
        strategyKey,
        stage: 'preflight_user_search',
        outcome: 'failure',
        level: 'warn',
        searchFilter: userSearchFilter,
        error: err,
        extra: {
          phase: 'startup_preflight_user_search',
          searchBaseDefined: !_.isEmpty(conf.searchBase)
        }
      })
      safeUnbind(client)
      return
    }

    if (conf.mapGroups) {
      try {
        const resolvedDn = resolveGroupDnValue(conf, userEntryCandidate, userDnCandidate)
        if (_.isEmpty(resolvedDn) && conf.groupSearchFilter && conf.groupSearchFilter.includes('{{dn}}')) {
          throw new Error(`Unable to resolve group DN property "${conf.groupDnProperty}" from LDAP user candidate`)
        }
        const groupFilter = interpolateGroupFilter(conf.groupSearchFilter, resolvedDn)
        const groupSearchResult = await searchEntries(client, conf.groupSearchBase, groupFilter, {
          scope: normalizeSearchScope(conf.groupSearchScope),
          sizeLimit: 5,
          timeLimit: 6,
          attributes: buildPreflightGroupAttributes(conf)
        })

        const groupValidation = validateGroupMapping(conf, groupSearchResult)
        if (!groupValidation.valid) {
          logLdapEvent({
            strategyKey,
            stage: 'preflight_group_search',
            outcome: 'failure',
            level: 'warn',
            error: new Error('LDAP preflight group mapping validation failed'),
            extra: {
              phase: 'startup_preflight_group_search',
              resultCount: groupSearchResult.count,
              groupValidationIssues: groupValidation.issues
            }
          })
          safeUnbind(client)
          return
        }

        logLdapEvent({
          strategyKey,
          stage: 'preflight_group_search',
          outcome: 'success',
          dn: resolvedDn,
          searchFilter: groupFilter,
          extra: {
            phase: 'startup_preflight_group_search',
            resultCount: groupSearchResult.count,
            usedFallbackDn: !userDnCandidate
          }
        })
      } catch (err) {
        logLdapEvent({
          strategyKey,
          stage: 'preflight_group_search',
          outcome: 'failure',
          level: 'warn',
          error: err,
          extra: {
            phase: 'startup_preflight_group_search',
            groupSearchBaseDefined: !_.isEmpty(conf.groupSearchBase),
            groupSearchFilterDefined: !_.isEmpty(conf.groupSearchFilter)
          }
        })
        safeUnbind(client)
        return
      }
    } else {
      logLdapEvent({
        strategyKey,
        stage: 'preflight_group_search',
        outcome: 'success',
        extra: {
          phase: 'startup_preflight_group_search_skipped',
          skipped: true,
          reason: 'mapGroups=false'
        }
      })
    }

    logLdapEvent({
      strategyKey,
      stage: 'preflight_success',
      outcome: 'success',
      extra: {
        phase: 'startup_preflight_completed'
      }
    })
    safeUnbind(client)
  },
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
            tlsEnabled: conf.tlsEnabled === true,
            phase: 'ldap_strategy_callback_entered'
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
              hasUniqueId: !_.isNil(userId),
              phase: 'ldap_profile_mapped'
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
                  currentGroupCount: currentGroups.length,
                  phase: 'ldap_group_mapping_completed'
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
                error: new Error('Group mapping enabled but LDAP groups payload is missing or invalid'),
                extra: {
                  phase: 'ldap_group_mapping_payload_invalid'
                }
              })
            }
          }
          logLdapEvent({
            req,
            strategyKey,
            stage: 'success',
            outcome: 'success',
            username: loginUsername,
            extra: {
              phase: 'ldap_strategy_callback_completed'
            }
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
            error: err,
            terminal: true,
            extra: {
              phase: 'ldap_strategy_callback_failed'
            }
          })
          cb(err, null)
        }
      }
      ))
  }
}

function bindClient(client, bindDn, bindCredentials) {
  return new Promise((resolve, reject) => {
    client.bind(bindDn, bindCredentials, err => {
      if (err) {
        return reject(err)
      }
      resolve()
    })
  })
}

function searchEntries(client, base, filter, opts = {}) {
  if (_.isEmpty(base)) {
    throw new Error('LDAP search base is empty')
  }
  if (_.isEmpty(filter)) {
    throw new Error('LDAP search filter is empty')
  }

  return new Promise((resolve, reject) => {
    const entries = []
    client.search(base, {
      filter,
      scope: opts.scope || 'sub',
      sizeLimit: _.toInteger(opts.sizeLimit) || 1,
      timeLimit: _.toInteger(opts.timeLimit) || 5,
      attributes: _.isArray(opts.attributes) ? opts.attributes : undefined
    }, (err, res) => {
      if (err) {
        return reject(err)
      }

      res.on('searchEntry', entry => {
        const dn = _.get(entry, 'objectName', _.get(entry, 'dn', null))
        const object = _.get(entry, 'object', {})
        entries.push({
          dn: dn ? String(dn) : null,
          object
        })
      })
      res.on('error', reject)
      res.on('end', result => {
        if (_.get(result, 'status', 0) !== 0) {
          return reject(new Error(`LDAP search ended with status ${result.status}`))
        }
        resolve({
          count: entries.length,
          entries
        })
      })
    })
  })
}

function buildPreflightUserSearchFilter(template) {
  if (!_.isString(template) || template.length < 1) {
    throw new Error('LDAP user searchFilter is missing')
  }

  // Preflight should validate the configured filter shape without assuming uid/mail semantics.
  // We only replace known placeholders with a synthetic probe identity.
  const probeIdentity = 'wiki-preflight@example.invalid'
  return template
    .replace(/\{\{username\}\}/g, escapeLdapValue(probeIdentity))
    .replace(/\{\{email\}\}/g, escapeLdapValue(probeIdentity))
    .replace(/\{\{user\}\}/g, escapeLdapValue(probeIdentity))
}

function buildPreflightUserAttributes(conf) {
  return _.uniq(_.compact([
    conf.mappingUID,
    conf.mappingEmail,
    conf.mappingDisplayName,
    conf.mappingPicture,
    conf.groupDnProperty
  ]))
}

function buildPreflightGroupAttributes(conf) {
  return _.uniq(_.compact([
    conf.groupNameField,
    'dn'
  ]))
}

function interpolateGroupFilter(template, dn) {
  if (!_.isString(template) || template.length < 1) {
    throw new Error('LDAP groupSearchFilter is missing while mapGroups=true')
  }
  return template.replace(/\{\{dn\}\}/g, escapeLdapValue(dn))
}

function validatePreflightConfig(conf) {
  const missingFields = []
  const invalidFields = []

  if (_.isEmpty(conf.url)) missingFields.push('url')
  if (_.isEmpty(conf.bindDn)) missingFields.push('bindDn')
  if (_.isEmpty(conf.bindCredentials)) missingFields.push('bindCredentials')
  if (_.isEmpty(conf.searchBase)) missingFields.push('searchBase')
  if (_.isEmpty(conf.searchFilter)) missingFields.push('searchFilter')

  if (conf.tlsEnabled && conf.verifyTLSCertificate && _.isEmpty(conf.tlsCertPath)) {
    missingFields.push('tlsCertPath')
  }

  if (_.isEmpty(conf.mappingUID)) missingFields.push('mappingUID')
  if (_.isEmpty(conf.mappingEmail)) missingFields.push('mappingEmail')
  if (_.isEmpty(conf.mappingDisplayName)) missingFields.push('mappingDisplayName')
  if (_.isEmpty(conf.mappingPicture)) missingFields.push('mappingPicture')

  if (conf.mapGroups) {
    if (_.isEmpty(conf.groupSearchBase)) missingFields.push('groupSearchBase')
    if (_.isEmpty(conf.groupSearchFilter)) missingFields.push('groupSearchFilter')
    if (_.isEmpty(conf.groupDnProperty)) missingFields.push('groupDnProperty')
    if (_.isEmpty(conf.groupNameField)) missingFields.push('groupNameField')
    const rawScope = _.toLower(_.trim(_.toString(conf.groupSearchScope || 'sub')))
    if (!_.includes(['base', 'one', 'sub'], rawScope)) {
      invalidFields.push('groupSearchScope')
    }
  }

  return {
    valid: missingFields.length === 0 && invalidFields.length === 0,
    missingFields,
    invalidFields
  }
}

function validateUserMappings(conf, userEntry) {
  if (!userEntry) {
    return {
      valid: false,
      userEntryFound: false,
      issues: ['searchFilter returned no candidate user entry; mappings cannot be validated']
    }
  }

  const issues = []
  const obj = _.get(userEntry, 'object', {})
  const checks = [
    ['mappingUID', conf.mappingUID],
    ['mappingEmail', conf.mappingEmail],
    ['mappingDisplayName', conf.mappingDisplayName],
    ['mappingPicture', conf.mappingPicture]
  ]

  for (const [label, fieldName] of checks) {
    if (_.isEmpty(fieldName)) {
      issues.push(`${label} is empty`)
      continue
    }
    if (!hasField(obj, fieldName)) {
      issues.push(`${label} field "${fieldName}" not found in LDAP user entry`)
    }
  }

  if (conf.mapGroups && !_.isEmpty(conf.groupDnProperty) && conf.groupDnProperty !== 'dn' && !hasField(obj, conf.groupDnProperty)) {
    issues.push(`groupDnProperty field "${conf.groupDnProperty}" not found in LDAP user entry`)
  }

  return {
    valid: issues.length === 0,
    userEntryFound: true,
    issues
  }
}

function validateGroupMapping(conf, groupSearchResult) {
  const issues = []
  if (groupSearchResult.count > 0) {
    const hasNameField = groupSearchResult.entries.some(entry => hasField(_.get(entry, 'object', {}), conf.groupNameField))
    if (!hasNameField) {
      issues.push(`groupNameField "${conf.groupNameField}" not found in returned LDAP group entries`)
    }
  }
  return {
    valid: issues.length === 0,
    issues
  }
}

function resolveGroupDnValue(conf, userEntry, fallbackDn) {
  const field = _.get(conf, 'groupDnProperty', 'dn')
  const userObj = _.get(userEntry, 'object', {})
  const mapped = _.get(userObj, field, null)
  if (!_.isNil(mapped) && mapped !== '') {
    return _.isArray(mapped) ? _.toString(_.first(mapped)) : _.toString(mapped)
  }
  if (field === 'dn') {
    return fallbackDn || null
  }
  return null
}

function hasField(obj, fieldName) {
  if (!obj || _.isEmpty(fieldName)) {
    return false
  }
  const value = _.get(obj, fieldName, undefined)
  if (_.isUndefined(value) || _.isNull(value)) {
    return false
  }
  if (_.isString(value)) {
    return value.length > 0
  }
  if (_.isArray(value)) {
    return value.length > 0
  }
  return true
}

function normalizeSearchScope(scope) {
  const normalized = _.toLower(_.trim(_.toString(scope || 'sub')))
  return _.includes(['base', 'one', 'sub'], normalized) ? normalized : 'sub'
}

function escapeLdapValue(value) {
  return String(value)
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\u0000/g, '\\00')
}

function safeUnbind(client) {
  if (!client) {
    return
  }
  try {
    client.unbind()
  } catch (err) {}
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
            tlsCertPath: conf.tlsCertPath,
            phase: 'ldap_tls_configuration'
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
