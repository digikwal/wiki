const _ = require('lodash')

const LDAP_DEBUG_MODES = {
  MASKED: 'MASKED',
  VERBOSE: 'VERBOSE'
}

function normalizeLdapDebugMode(mode) {
  if (!_.isString(mode)) {
    return LDAP_DEBUG_MODES.MASKED
  }
  const normalized = _.toUpper(mode)
  return LDAP_DEBUG_MODES[normalized] || LDAP_DEBUG_MODES.MASKED
}

function toBool(value, fallback = false) {
  if (_.isBoolean(value)) {
    return value
  }
  if (_.isNumber(value)) {
    return value === 1
  }
  if (_.isString(value)) {
    const v = _.toLower(_.trim(value))
    if (v === 'true' || v === '1') return true
    if (v === 'false' || v === '0') return false
  }
  return fallback
}

function getDevFlags(config = _.get(global, 'WIKI.config', {})) {
  return {
    ldapDebugEnabled: toBool(_.get(config, 'devFlags.ldapDebugEnabled', _.get(config, 'flags.ldapdebug', false))),
    ldapDebugMode: normalizeLdapDebugMode(_.get(config, 'devFlags.ldapDebugMode', LDAP_DEBUG_MODES.MASKED)),
    sqlLog: toBool(_.get(config, 'devFlags.sqlLog', _.get(config, 'flags.sqllog', false)))
  }
}

function isLdapDebugEnabled(config) {
  return getDevFlags(config).ldapDebugEnabled
}

module.exports = {
  LDAP_DEBUG_MODES,
  getDevFlags,
  isLdapDebugEnabled,
  normalizeLdapDebugMode
}
