# Usage and API

All examples run inside an async function after Cordova `deviceready`. They call
the public JavaScript module registered by plugin.xml. Consumer functions such
as consumeKey are placeholders supplied by the caller.

## Versioned interfaces

Wait for deviceready and access UltraSecureStorage. V1, V2 and V3 are separate
storage policies/namespaces, not package release versions.

| Policy       | Methods                                                                                                                     |
| ------------ | --------------------------------------------------------------------------------------------------------------------------- |
| V1           | set, get, has, remove, clear                                                                                                |
| V2 biometric | setBiometric, getBiometric, hasBiometric, removeBiometric, clearBiometric                                                   |
| V3 session   | configureSession, unlockSession, lockSession, sessionState, setSession, getSession, hasSession, removeSession, clearSession |
| Capability   | biometricStatus                                                                                                             |

Native operations return promises; invalid key/value arguments can throw
synchronously before dispatch. Use try/await/catch to handle both paths. set
methods take key and string value; get, has and remove take key. V2 set/get
additionally accept prompt options. Missing get rejects with a NotFoundError
whose code is the string NOT_FOUND; has is a boolean probe. clear removes the
entire selected namespace.

```js
const storage = UltraSecureStorage
await storage.set('example', 'example value')
const value = await storage.get('example')
await storage.remove('example')

await storage.configureSession({ timeoutMs: 300000, lockOnBackground: true })
await storage.unlockSession({ reason: 'Unlock protected storage' })
try {
  await storage.setSession('example', 'protected example')
} finally {
  await storage.lockSession()
}
```

Never silently downgrade biometric/session access to V1 after denial. Avoid
logging value or keeping secrets in UI state. JavaScript string values cannot be
reliably erased in place. See the developer guide for prompt configuration,
platform setup, key constraints and lifecycle behavior.

## Errors and lifecycle

Handle rejected promises or failure callbacks explicitly. Do not substitute
plaintext, predictable keys or weaker algorithms after failure. Keep caller
buffers valid until async work completes, and wipe only buffers you own.

[Developer guide](../DEVELOPMENT.md) · [Security policy](../SECURITY.md) ·
[README](../README.md)
