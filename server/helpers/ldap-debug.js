const crypto = require('crypto')
const _ = require('lodash')

const { getDevFlags, LDAP_DEBUG_MODES } = require('./dev-flags')

function createTraceId() {
  return crypto.randomBytes(8).toString('hex')
}

function getTraceId(req) {
  return _.get(req, 'ldapDebug.traceId', null)
}

function setTraceId(req, traceId) {
  if (!req || !traceId) {
    return
  }
  _.set(req, 'ldapDebug.traceId', traceId)
}

function isTerminalFailureLogged(req) {
  return _.get(req, 'ldapDebug.terminalFailureLogged', false) === true
}

function setTerminalFailureLogged(req) {
  if (!req) {
    return
  }
  _.set(req, 'ldapDebug.terminalFailureLogged', true)
}

function getUsernameToken(username) {
  if (!username) {
    return null
  }
  const secret = _.get(global, 'WIKI.config.sessionSecret', 'wiki-ldap-debug')
  return crypto
    .createHmac('sha256', secret)
    .update(String(username))
    .digest('hex')
    .substring(0, 12)
}

function getErrorData(err) {
  if (!err) {
    return {
      errorClass: null,
      errorCode: null,
      errorMessage: null
    }
  }
  return {
    errorClass: err.name || 'Error',
    errorCode: _.get(err, 'code', null),
    errorMessage: err.message || String(err)
  }
}

function logLdapEvent({
  req,
  strategyKey = null,
  stage,
  outcome,
  level = 'info',
  username = null,
  dn = null,
  searchFilter = null,
  error = null,
  terminal = false,
  extra = {}
}) {
  const { ldapDebugEnabled, ldapDebugMode } = getDevFlags()
  if (!ldapDebugEnabled) {
    return
  }

  if (terminal && isTerminalFailureLogged(req)) {
    return
  }

  const traceId = getTraceId(req)
  const basePayload = {
    event: `ldap.login.${stage}`,
    traceId,
    strategyKey,
    stage,
    outcome,
    ...getErrorData(error)
  }

  if (ldapDebugMode === LDAP_DEBUG_MODES.VERBOSE) {
    basePayload.username = username || null
    basePayload.dn = dn || null
    basePayload.searchFilter = searchFilter || null
  } else {
    basePayload.usernameToken = getUsernameToken(username)
    basePayload.dn = dn ? '[REDACTED]' : null
    basePayload.searchFilter = searchFilter ? '[REDACTED]' : null
  }

  const payload = {
    ...basePayload,
    ...extra
  }

  const logger = _.get(global, 'WIKI.logger')
  if (!logger) {
    return
  }
  const logLevel = _.has(logger, level) ? level : 'info'
  logger[logLevel](`[LDAP DEBUG] ${JSON.stringify(payload)}`)

  if (terminal) {
    setTerminalFailureLogged(req)
  }
}

module.exports = {
  createTraceId,
  getTraceId,
  setTraceId,
  logLdapEvent,
  getUsernameToken,
  isTerminalFailureLogged
}
