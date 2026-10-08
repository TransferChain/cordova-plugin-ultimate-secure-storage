var exec = require('cordova/exec')

var SERVICE = 'UltraSecureStorage'

class NotFoundError extends Error {
  constructor(message) {
    super(message)
    this.name = 'NotFoundError'
    this.code = 'NOT_FOUND'
  }
}

// This standalone Cordova module cannot depend on application aliases or error
// classes. Preserve native error codes and reject missing reads as NotFoundError.
function makeError(error) {
  if (error && error.code === 'NOT_FOUND') {
    return new NotFoundError('Key does not exists!')
  }

  if (error instanceof Error) return error

  var e = new Error(
    error && error.message
      ? error.message
      : String(error || 'Unknown secure storage error')
  )

  if (error && error.code) e.code = error.code

  return e
}

// Keep action names and argument order aligned across both native platforms.
// Update DEVELOPMENT.md and bridge tests when adding an action.
function call(action, args) {
  return new Promise(function (resolve, reject) {
    exec(
      resolve,
      function (error) {
        reject(makeError(error))
      },
      SERVICE,
      action,
      args || []
    )
  })
}

function validateKey(key) {
  if (typeof key !== 'string' || key.length === 0) {
    throw new TypeError('UltraSecureStorage key must be a non-empty string.')
  }
}

function validateValue(value) {
  if (typeof value !== 'string') {
    throw new TypeError('UltraSecureStorage value must be a string.')
  }
}

function normalizePrompt(options) {
  options = options || {}
  return {
    title:
      typeof options.title === 'string' && options.title
        ? options.title
        : 'Unlock secure data',
    reason:
      typeof options.reason === 'string' && options.reason
        ? options.reason
        : 'Authenticate to access protected secure data'
  }
}

// VERSIONED STORAGE CONTRACT
//
// This plugin exposes three separate storage namespaces, not three interchangeable
// fallbacks. V1 uses OS-protected storage. V2 protects reads/writes with biometric
// authentication for each operation. V3 unlocks an application session whose
// subsequent operations check idle/background locking policy.
//
// For example, set('name', 'value') writes V1; getBiometric('name') reads V2 and
// must not search V1 if the key is absent. Values are strings: serialize structured
// data in the application layer. An empty string is valid, while missing reads
// reject with NOT_FOUND. has* methods answer existence and do not grant read access.
//
// The Promise is tied to one native callback. Do not resolve a write before native
// persistence succeeds or translate authentication failure into a missing value.
// The application uses its secure-storage store for version selection and error
// mapping; keep app imports out of this independently installable Cordova module.
module.exports = {
  // V1: OS-protected storage at rest, without a per-operation biometric prompt.
  set: function (key, value) {
    validateKey(key)
    validateValue(value)
    return call('set', [key, value]).then(function () {})
  },

  get: function (key) {
    validateKey(key)
    return call('get', [key]).then(function (value) {
      // An empty string is a valid stored value. Reject only null/undefined here;
      // using a truthiness check would incorrectly report empty values as missing.
      if (value == null) {
        return Promise.reject(new NotFoundError('Key does not exists!'))
      }

      return value
    })
  },

  remove: function (key) {
    validateKey(key)
    return call('remove', [key]).then(function () {})
  },

  clear: function () {
    return call('clear', []).then(function () {})
  },

  has: function (key) {
    validateKey(key)
    return call('has', [key]).then(function (value) {
      return value === true
    })
  },

  // V2: Protected reads/writes require per-operation biometric authentication.
  biometricStatus: function () {
    return call('biometricStatus', [])
  },

  setBiometric: function (key, value, options) {
    validateKey(key)
    validateValue(value)
    var prompt = normalizePrompt(options)

    return call('setBiometric', [key, value, prompt]).then(function () {})
  },

  getBiometric: function (key, options) {
    validateKey(key)
    var prompt = normalizePrompt(options)

    return call('getBiometric', [key, prompt]).then(function (value) {
      if (value == null) {
        return Promise.reject(new NotFoundError('Key does not exists!'))
      }

      return value
    })
  },

  hasBiometric: function (key) {
    validateKey(key)
    return call('hasBiometric', [key]).then(function (value) {
      return value === true
    })
  },

  removeBiometric: function (key) {
    validateKey(key)
    return call('removeBiometric', [key]).then(function () {})
  },

  clearBiometric: function () {
    return call('clearBiometric', []).then(function () {})
  },

  // V3: Biometric application session with idle/background locking.
  configureSession: function (options) {
    options = options || {}

    // Session timeout is expressed in milliseconds. The native layer enforces
    // the actual lock state; these options do not themselves unlock the session.
    var timeoutMs = Number.isFinite(options.timeoutMs)
        ? Math.max(1000, Math.floor(options.timeoutMs))
        : 300000,
      lockOnBackground = options.lockOnBackground !== false

    return call('configureSession', [
      {
        timeoutMs: timeoutMs,
        lockOnBackground: lockOnBackground
      }
    ])
  },

  unlockSession: function (options) {
    var prompt = normalizePrompt(options)

    return call('unlockSession', [prompt])
  },

  lockSession: function () {
    return call('lockSession', [])
  },

  sessionState: function () {
    return call('sessionState', [])
  },

  setSession: function (key, value) {
    validateKey(key)
    validateValue(value)
    return call('setSession', [key, value]).then(function () {})
  },

  getSession: function (key) {
    validateKey(key)
    return call('getSession', [key]).then(function (value) {
      if (value == null) {
        return Promise.reject(new NotFoundError('Key does not exists!'))
      }

      return value
    })
  },

  hasSession: function (key) {
    validateKey(key)
    return call('hasSession', [key]).then(function (value) {
      return value === true
    })
  },

  removeSession: function (key) {
    validateKey(key)
    return call('removeSession', [key]).then(function () {})
  },

  clearSession: function () {
    return call('clearSession', []).then(function () {})
  }
}
