# Test layout and verification

Paths below are relative to the plugin root. Run tests in a disposable Cordova
test host containing this plugin; never use production credentials.

## Cordova JavaScript tests

Load tests/js/secure-storage-tests.js or secure-storage-v2-v3-tests.js in a
dedicated Cordova test host and invoke the exported helper after deviceready,
following the comments in each file. These are device helpers, not Mocha
bridge.test.js suites. They can clear namespaces; use only disposable test data.
Android inspection helpers are in tests/android/.

## Android and iOS

- tests/android/ contains Android instrumentation sources. Configure the test
  host with Cordova, the plugin and AndroidX test dependencies, and add these
  sources to its androidTest source set. Build and execute the selected
  instrumentation suite on an emulator or device.
- tests/ios/ contains XCTest sources and test support. Configure a Cordova test
  host and the required support module in Xcode, include the plugin sources and
  run the selected suite on macOS with a simulator or device.

The package provides test sources, not a standalone Gradle/Xcode test project or
application-level runner commands. Check the imports and support files when
configuring your host. Compilation and test-source preparation are not proof of
execution. Run validation jobs serially.

Storage suites use synthetic keys and per-key cleanup. Configure Keychain
entitlements for the iOS host. Real biometric success/cancellation, enrollment
changes and expiry after unlock require explicit interactive scenarios. A
skipped biometric case must remain reported as skipped; never add an
authentication bypass to production for a test.

See [README security results](../README.md#security) for recorded validation and
its limits, and [DEVELOPMENT.md](../DEVELOPMENT.md) for native invariants.
