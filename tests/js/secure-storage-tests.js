export async function runSecureStorageTests(
  storage = window.UltraSecureStorage
) {
  const results = [],
    record = (name, ok, detail = '') => {
      const row = { name, ok, detail }

      results.push(row)
      const fn = ok ? console.log : console.error

      fn(
        `[UltraSecureStorage Test] ${ok ? 'PASS' : 'FAIL'} - ${name}${detail ? `: ${detail}` : ''}`
      )
    },
    assert = (condition, message) => {
      if (!condition) throw new Error(message || 'Assertion failed')
    }

  async function expectMissing(key) {
    try {
      await storage.get(key)
    } catch (error) {
      assert(error?.code === 'NOT_FOUND', 'Expected NOT_FOUND')
      return
    }

    assert(false, 'Missing key must reject')
  }

  try {
    await storage.clear()
    record('Initial clear()', true)
  } catch (err) {
    record('Initial clear()', false, err?.message || String(err))
    return results
  }

  // Missing key
  try {
    assert(
      (await storage.has('missing-key')) === false,
      'has() must return false'
    )
    await expectMissing('missing-key')
    record('Missing key behavior', true)
  } catch (err) {
    record('Missing key behavior', false, err.message)
  }

  // Basic set/get/has
  try {
    await storage.set('alpha', 'secret-1')
    assert((await storage.has('alpha')) === true, 'has(alpha) must be true')
    assert((await storage.get('alpha')) === 'secret-1', 'get(alpha) mismatch')
    record('set/get/has', true)
  } catch (err) {
    record('set/get/has', false, err.message)
  }

  // Overwrite
  try {
    await storage.set('alpha', 'secret-2')
    assert((await storage.get('alpha')) === 'secret-2', 'overwrite failed')
    record('Overwrite existing key', true)
  } catch (err) {
    record('Overwrite existing key', false, err.message)
  }

  // Empty string value
  try {
    await storage.set('empty-value', '')
    assert((await storage.get('empty-value')) === '', 'empty string mismatch')
    record('Empty string value', true)
  } catch (err) {
    record('Empty string value', false, err.message)
  }

  // UTF-8
  try {
    const utf8 = 'şifre🔐日本語مرحبا'

    await storage.set('utf8', utf8)
    assert((await storage.get('utf8')) === utf8, 'UTF-8 mismatch')
    record('UTF-8 roundtrip', true)
  } catch (err) {
    record('UTF-8 roundtrip', false, err.message)
  }

  // Remove
  try {
    await storage.set('remove-me', 'value')
    await storage.remove('remove-me')
    assert(
      (await storage.has('remove-me')) === false,
      'removed key still exists'
    )
    await expectMissing('remove-me')
    record('remove()', true)
  } catch (err) {
    record('remove()', false, err.message)
  }

  // clear()
  try {
    await storage.set('clear-a', 'one')
    await storage.set('clear-b', 'two')
    await storage.clear()
    assert((await storage.has('clear-a')) === false, 'clear-a still exists')
    assert((await storage.has('clear-b')) === false, 'clear-b still exists')
    await expectMissing('clear-a')
    await expectMissing('clear-b')
    record('clear()', true)
  } catch (err) {
    record('clear()', false, err.message)
  }

  // Invalid key
  try {
    await storage.set('', 'x')
    record('Reject empty key', false, 'Expected rejection')
  } catch (err) {
    record('Reject empty key', true, err?.message || String(err))
  }

  // Oversized key
  try {
    await storage.set('k'.repeat(1025), 'x')
    record('Reject key > 1024 chars', false, 'Expected rejection')
  } catch (err) {
    record('Reject key > 1024 chars', true, err?.message || String(err))
  }

  // 64 KiB exact UTF-8 payload
  try {
    const exact64KiB = 'a'.repeat(64 * 1024)

    await storage.set('boundary-64k', exact64KiB)
    assert(
      (await storage.get('boundary-64k')) === exact64KiB,
      '64 KiB value mismatch'
    )
    record('Accept exact 64 KiB value', true)
  } catch (err) {
    record('Accept exact 64 KiB value', false, err.message)
  }

  // 64 KiB + 1
  try {
    await storage.set('boundary-too-large', 'a'.repeat(64 * 1024 + 1))
    record('Reject value > 64 KiB', false, 'Expected rejection')
  } catch (err) {
    record('Reject value > 64 KiB', true, err?.message || String(err))
  }

  // Repeated overwrite / stability
  try {
    for (let i = 0; i < 100; i++) {
      const value = `value-${i}`

      await storage.set('stress-key', value)
      const read = await storage.get('stress-key')

      assert(read === value, `Mismatch at iteration ${i}`)
    }

    record('100x overwrite/read stress', true)
  } catch (err) {
    record('100x overwrite/read stress', false, err.message)
  }

  // Prepare known value for restart/reboot test
  try {
    await storage.set('persist-test', 'persist-value')
    record(
      'Prepare persistence value',
      true,
      'Force-stop/restart app and run runPersistenceCheck()'
    )
  } catch (err) {
    record('Prepare persistence value', false, err.message)
  }

  const passed = results.filter((r) => r.ok).length,
    failed = results.length - passed

  console.log(
    `[UltraSecureStorage Test] Completed: ${passed} passed, ${failed} failed`
  )
  return { passed, failed, results }
}

export async function runPersistenceCheck(storage = window.UltraSecureStorage) {
  const value = await storage.get('persist-test'),
    ok = value === 'persist-value',
    result = {
      name: 'Persistence after restart/reboot',
      ok,
      expected: 'persist-value',
      actual: value
    }

  console[ok ? 'log' : 'error'](
    `[UltraSecureStorage Test] ${ok ? 'PASS' : 'FAIL'} - Persistence after restart/reboot`
  )

  return result
}

export async function writeRandomizationSample(
  storage = window.UltraSecureStorage,
  iteration = 1
) {
  // Intentionally same logical key and same plaintext each time.
  // Inspect SharedPreferences after each call using the ADB helper script.
  await storage.set(
    'randomization-test',
    'TRANSFERCHAIN_IDENTICAL_RANDOMIZATION_PLAINTEXT'
  )

  console.log(
    `[UltraSecureStorage Test] Randomization sample ${iteration} written. ` +
      `Now snapshot SharedPreferences with adb.`
  )
}

export async function prepareTamperSample(storage = window.UltraSecureStorage) {
  await storage.set('tamper-test', 'TRANSFERCHAIN_TAMPER_TEST_SECRET')
  console.log('[UltraSecureStorage Test] Tamper sample prepared.')
}

export async function verifyTamperFailure(storage = window.UltraSecureStorage) {
  try {
    const value = await storage.get('tamper-test')

    return {
      ok: false,
      detail: `Decryption unexpectedly succeeded: ${value}`
    }
  } catch (err) {
    return {
      ok: true,
      detail: err?.message || String(err)
    }
  }
}
