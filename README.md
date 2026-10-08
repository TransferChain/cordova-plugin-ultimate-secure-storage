# cordova-plugin-ultimate-secure-storage

Versioned Android Keystore and Apple Keychain storage with biometric support.

## Installation

Install from the TransferChain GitHub repository:

```sh
cordova plugin add https://github.com/TransferChain/cordova-plugin-ultimate-secure-storage
```

Wait for Cordova's deviceready event before calling UltraSecureStorage. This
package targets Android and iOS; it does not provide a browser fallback. The
command targets the GitHub repository; repository publication is managed
separately. This document does not imply an npm release is available.

## iOS validation status

iOS testing is ongoing. Progress and validation updates will be shared
regularly. XCTest sources are available, but macOS/Xcode execution has not yet
been completed; verified iOS security behavior is not claimed.

## Documentation

- [Usage, parameters and examples](docs/API.md)
- [Tests and verification](docs/TESTING.md)
- [Native implementation guide](DEVELOPMENT.md)

## Plugin entry point

After Cordova's `deviceready` event, access `window.UltraSecureStorage`. The
methods below belong to that plugin object. See [API examples](docs/API.md) for
parameters, results and cleanup.

## API

```text
V1: set, get, has, remove, clear
V2: setBiometric, getBiometric, hasBiometric, removeBiometric, clearBiometric
V3: setSession, getSession, hasSession, removeSession, clearSession
Session: configureSession, unlockSession, lockSession, sessionState
Capability: biometricStatus
```

See [the developer guide](DEVELOPMENT.md) for argument details, native
implementation, lifecycle, failure behavior and platform prerequisites. Keys and
values are strings. V1, V2 and V3 use separate namespaces; select the required
methods explicitly. Missing reads reject with NOT_FOUND.

## Tests and development

Plugin test sources live under tests/. See [test setup](docs/TESTING.md) for the
suites included in this package and their harness requirements. Native checks
require the Android or Xcode toolchain. A host mock passing is not evidence that
Android or iOS device execution succeeded.

## Contributing

Read the [contribution guidelines](CONTRIBUTING.md) for development setup,
coding conventions, regression tests and pull request expectations.

## Security

Recorded security-related regression results:

- Android emulator, 2026-10-08: 6 instrumentation cases passed, 1 biometric
  scenario was explicitly skipped, with no failures or errors.
- Passed coverage includes V1 roundtrip/overwrite/missing reads, V2
  noninteractive capability failures, locked V3/configuration/lifecycle,
  distinct-key parallel writes and stale unlock-completion rejection after lock,
  reset and background revocation.
- The stale-completion test exercised the real commit guard with a revoked
  generation; it did not bypass authentication. Real biometric success,
  cancellation, enrollment changes and expiry after unlock remain pending.

These are results from the dated validation runs, not a new execution for this
documentation update. Android results are emulator results; they do not
establish physical-device or iOS validation. Host mocks do not prove native
execution. Passing regressions are not a security audit or certification. See
[test setup and scope](docs/TESTING.md).

Read [SECURITY.md](SECURITY.md) to report a vulnerability. Never include
production credentials or secret values in reports or logs.

## License

[MIT](LICENSE), TransferChain AG. Dependencies and vendored components retain
their respective licenses and attribution requirements.
