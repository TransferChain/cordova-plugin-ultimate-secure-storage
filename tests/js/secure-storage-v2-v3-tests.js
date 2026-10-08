export async function runV2V3Tests(storage = window.UltraSecureStorage) {
  const results = [],
    add = (name, ok, detail = '') => {
      results.push({ name, ok, detail })
      console[ok ? 'log' : 'error'](
        `[UltraSecureStorage V2/V3] ${ok ? 'PASS' : 'FAIL'} - ${name}${detail ? ': ' + detail : ''}`
      )
    },
    biometric = await storage.biometricStatus()

  add(
    'Biometric status',
    typeof biometric.available === 'boolean',
    JSON.stringify(biometric)
  )

  if (!biometric.available) {
    add(
      'Biometric protected tests',
      false,
      'Strong biometrics are unavailable/enrollment missing on this device'
    )
    return { results }
  }

  // V2 requires an interactive biometric prompt.
  try {
    await storage.setBiometric('v2-secret', 'v2-secret-value', {
      reason: 'Store a protected test secret'
    })
    add('V2 setBiometric', true)
  } catch (err) {
    add('V2 setBiometric', false, err?.message || String(err))
  }

  try {
    const exists = await storage.hasBiometric('v2-secret')

    add('V2 hasBiometric', exists === true)
  } catch (err) {
    add('V2 hasBiometric', false, err?.message || String(err))
  }

  try {
    const value = await storage.getBiometric('v2-secret', {
      reason: 'Read a protected test secret'
    })

    add('V2 getBiometric', value === 'v2-secret-value')
  } catch (err) {
    add('V2 getBiometric', false, err?.message || String(err))
  }

  // V3
  try {
    const state = await storage.configureSession({
      timeoutMs: 5000,
      lockOnBackground: true
    })

    add('V3 configureSession', state.timeoutMs === 5000)
  } catch (err) {
    add('V3 configureSession', false, err?.message || String(err))
  }

  try {
    await storage.lockSession()
    let rejected = false

    try {
      await storage.getSession('v3-secret')
    } catch (err) {
      rejected =
        err?.code === 'SESSION_LOCKED' || /locked/i.test(err?.message || '')
    }

    add('V3 locked access rejected', rejected)
  } catch (err) {
    add('V3 locked access rejected', false, err?.message || String(err))
  }

  try {
    const state = await storage.unlockSession({
      reason: 'Unlock secure test session'
    })

    add('V3 biometric session unlock', state.unlocked === true)
  } catch (err) {
    add('V3 biometric session unlock', false, err?.message || String(err))
  }

  try {
    await storage.setSession('v3-secret', 'v3-secret-value')
    const value = await storage.getSession('v3-secret')

    add('V3 session set/get', value === 'v3-secret-value')
  } catch (err) {
    add('V3 session set/get', false, err?.message || String(err))
  }

  try {
    await storage.lockSession()
    const state = await storage.sessionState()

    add('V3 explicit lock', state.unlocked === false)
  } catch (err) {
    add('V3 explicit lock', false, err?.message || String(err))
  }

  return { results }
}

export async function runSessionTimeoutTest(
  storage = window.UltraSecureStorage,
  timeoutMs = 2000
) {
  await storage.configureSession({
    timeoutMs,
    lockOnBackground: false
  })

  await storage.unlockSession({
    reason: 'Unlock for session timeout test'
  })

  await new Promise((resolve) => setTimeout(resolve, timeoutMs + 500))
  const state = await storage.sessionState()

  return {
    ok: state.unlocked === false,
    state
  }
}

export async function runBackgroundLockPreparation(
  storage = window.UltraSecureStorage
) {
  await storage.configureSession({
    timeoutMs: 60000,
    lockOnBackground: true
  })

  return storage.unlockSession({
    reason: 'Unlock before background-lock test'
  })
}

export async function verifyBackgroundLocked(
  storage = window.UltraSecureStorage
) {
  const state = await storage.sessionState()

  return {
    ok: state.unlocked === false,
    state
  }
}
