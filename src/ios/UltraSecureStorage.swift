#if canImport(Cordova)
import Cordova
#endif

import Foundation
import Security
import LocalAuthentication
import UIKit

@objc(UltraSecureStorage)
class UltraSecureStorage: CDVPlugin {

    // Separate Keychain services isolate version-specific access policies.
    // V2 uses item access control; V3 uses application session checks.
    private let v1Service = "com.transferchain.securestorage.v1"
    private let v2Service = "com.transferchain.securestorage.biometric.v2"
    private let v3Service = "com.transferchain.securestorage.session.v3"

    private let maxKeyLength = 1024
    private let maxValueBytes = 64 * 1024

    // V3 memory-only session state.
    // SESSION TYPES AND EXECUTION ASSUMPTIONS
    // Bool stores authorization; Double matches Foundation's systemUptime seconds
    // and the configured millisecond timeout. Comparison converts elapsed units.
    // Wall-clock Date is unsuitable because clock adjustments can change idle policy.
    // These ordinary Swift fields are not atomics. Cordova selectors, UIKit lifecycle
    // notifications and main-queue biometric completion define the current access
    // path. Moving access to new queues requires revisiting synchronization; the
    // bool alone cannot coordinate arbitrary concurrent session transitions.
    private var sessionUnlocked = false
    private var sessionLastActivity = ProcessInfo.processInfo.systemUptime
    private var sessionTimeoutMs: Double = 5 * 60 * 1000
    private var sessionLockOnBackground = true
    private var sessionGeneration = UUID()

    override func pluginInitialize() {
        lockSessionInternal()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appDidEnterBackground),
            name: UIApplication.didEnterBackgroundNotification,
            object: nil
        )
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    override func onReset() {
        lockSessionInternal()
    }

    @objc private func appDidEnterBackground() {
        if sessionLockOnBackground {
            lockSessionInternal()
        }
    }

    // MARK: - V1

    @objc func set(_ command: CDVInvokedUrlCommand) {
        setKeychainItem(command, service: v1Service,
                        accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    @objc func get(_ command: CDVInvokedUrlCommand) {
        getKeychainItem(command, service: v1Service)
    }

    @objc func remove(_ command: CDVInvokedUrlCommand) {
        removeKeychainItem(command, service: v1Service)
    }

    @objc func clear(_ command: CDVInvokedUrlCommand) {
        clearKeychain(command, service: v1Service)
    }

    @objc func has(_ command: CDVInvokedUrlCommand) {
        hasKeychainItem(command, service: v1Service)
    }

    // MARK: - V2 Biometric

    @objc func biometricStatus(_ command: CDVInvokedUrlCommand) {
        let context = LAContext()
        var error: NSError?

        let available = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        )

        var type = "none"
        if available {
            switch context.biometryType {
            case .faceID:
                type = "face"
            case .touchID:
                type = "fingerprint"
            default:
                if #available(iOS 17.0, *), context.biometryType == .opticID {
                    type = "iris"
                } else {
                    type = "unknown"
                }
            }
        }

        let result: [String: Any] = [
            "available": available,
            "type": type,
            "strong": available,
            "code": error?.code ?? 0
        ]

        sendObject(command, result)
    }

    @objc func setBiometric(_ command: CDVInvokedUrlCommand) {
        guard
            let key = command.argument(at: 0) as? String,
            let value = command.argument(at: 1) as? String
        else {
            sendError(command, code: "INVALID_ARGUMENT",
                      message: "setBiometric() requires key and value strings.")
            return
        }

        do {
            try validateKey(key)
            let data = try validateAndEncodeValue(value)
            let prompt = promptOptions(command.argument(at: 2))

            authenticateBiometrics(prompt.reason) { [weak self] context, error in
                guard let self = self else { return }

                if let error = error {
                    self.sendError(command, code: "BIOMETRIC_AUTH_ERROR",
                                   message: error.localizedDescription)
                    return
                }

                do {
                    try self.replaceBiometricItem(
                        key: key,
                        data: data,
                        context: context
                    )
                    self.sendSuccess(command)
                } catch {
                    self.sendCaughtError(command, code: "BIOMETRIC_SET_FAILED", error: error)
                }
            }
        } catch {
            sendCaughtError(command, code: "BIOMETRIC_SET_FAILED", error: error)
        }
    }

    @objc func getBiometric(_ command: CDVInvokedUrlCommand) {
        guard let key = command.argument(at: 0) as? String else {
            sendError(command, code: "INVALID_ARGUMENT",
                      message: "getBiometric() requires a key string.")
            return
        }

        do {
            try validateKey(key)
            let prompt = promptOptions(command.argument(at: 1))

            if !biometricItemExists(key) {
                sendError(command, code: "NOT_FOUND", message: "Key does not exists!")
                return
            }

            authenticateBiometrics(prompt.reason) { [weak self] context, error in
                guard let self = self else { return }

                if let error = error {
                    self.sendError(command, code: "BIOMETRIC_AUTH_ERROR",
                                   message: error.localizedDescription)
                    return
                }

                do {
                    let value = try self.readBiometricItem(key: key, context: context)
                    let result = CDVPluginResult(
                        status: CDVCommandStatus_OK,
                        messageAs: value
                    )

                    self.commandDelegate.send(result, callbackId: command.callbackId)
                } catch {
                    self.sendCaughtError(command, code: "BIOMETRIC_GET_FAILED", error: error)
                }
            }
        } catch {
            sendCaughtError(command, code: "BIOMETRIC_GET_FAILED", error: error)
        }
    }

    @objc func hasBiometric(_ command: CDVInvokedUrlCommand) {
        guard let key = command.argument(at: 0) as? String else {
            sendError(command, code: "INVALID_ARGUMENT",
                      message: "hasBiometric() requires a key string.")
            return
        }

        do {
            try validateKey(key)
            sendBool(command, value: biometricItemExists(key))
        } catch {
            sendCaughtError(command, code: "BIOMETRIC_HAS_FAILED", error: error)
        }
    }

    @objc func removeBiometric(_ command: CDVInvokedUrlCommand) {
        removeKeychainItem(command, service: v2Service)
    }

    @objc func clearBiometric(_ command: CDVInvokedUrlCommand) {
        clearKeychain(command, service: v2Service)
    }

    // MARK: - V3 Session

    @objc func configureSession(_ command: CDVInvokedUrlCommand) {
        if let options = command.argument(at: 0) as? [String: Any] {
            if let timeout = options["timeoutMs"] as? NSNumber {
                sessionTimeoutMs = max(1000, timeout.doubleValue)
            }

            if let lock = options["lockOnBackground"] as? Bool {
                sessionLockOnBackground = lock
            }
        }

        sendSessionState(command)
    }

    @objc func unlockSession(_ command: CDVInvokedUrlCommand) {
        let prompt = promptOptions(command.argument(at: 0))
        let generation = sessionGeneration

        // V3 SESSION TRANSITION
        // Authentication completion can arrive after this method returns. Retain no
        // strong cycle through the plugin: weak self allows teardown while the prompt
        // is pending. A failure explicitly leaves the session locked.
        //
        // Only successful authentication sets the session flag and starts the idle clock.
        // Later V3 methods must still call requireUnlockedSession before accessing data;
        // unlock is not a permanent capability and does not change V2 Keychain policies.
        authenticateBiometrics(prompt.reason) { [weak self] _, error in
            guard let self = self else { return }

            // Cordova actions and LAContext completion publish on the main queue.
            // A revoked request must never reopen or modify a newer session.
            guard generation == self.sessionGeneration else {
                self.sendError(command, code: "SESSION_LOCKED",
                               message: "Secure session is locked.")
                return
            }

            if let error = error {
                self.lockSessionInternal()
                self.sendError(command, code: "SESSION_UNLOCK_FAILED",
                               message: error.localizedDescription)
                return
            }

            self.sessionUnlocked = true
            self.touchSession()
            self.sendSessionState(command)
        }
    }

    @objc func lockSession(_ command: CDVInvokedUrlCommand) {
        lockSessionInternal()
        sendSessionState(command)
    }

    @objc func sessionState(_ command: CDVInvokedUrlCommand) {
        sendSessionState(command)
    }

    @objc func setSession(_ command: CDVInvokedUrlCommand) {
        guard requireUnlockedSession(command) else { return }

        touchSession()
        setKeychainItem(command, service: v3Service,
                        accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    @objc func getSession(_ command: CDVInvokedUrlCommand) {
        guard requireUnlockedSession(command) else { return }

        touchSession()
        getKeychainItem(command, service: v3Service)
    }

    @objc func hasSession(_ command: CDVInvokedUrlCommand) {
        guard requireUnlockedSession(command) else { return }

        touchSession()
        hasKeychainItem(command, service: v3Service)
    }

    @objc func removeSession(_ command: CDVInvokedUrlCommand) {
        guard requireUnlockedSession(command) else { return }

        touchSession()
        removeKeychainItem(command, service: v3Service)
    }

    @objc func clearSession(_ command: CDVInvokedUrlCommand) {
        guard requireUnlockedSession(command) else { return }

        touchSession()
        clearKeychain(command, service: v3Service)
    }

    private func requireUnlockedSession(_ command: CDVInvokedUrlCommand) -> Bool {
        if !isSessionUnlockedInternal() {
            lockSessionInternal()
            sendError(command, code: "SESSION_LOCKED",
                      message: "Secure session is locked.")
            return false
        }

        return true
    }

    private func isSessionUnlockedInternal() -> Bool {
        guard sessionUnlocked else { return false }

        let elapsedMs =
            (ProcessInfo.processInfo.systemUptime - sessionLastActivity) * 1000

        if elapsedMs >= sessionTimeoutMs {
            lockSessionInternal()
            return false
        }

        return true
    }

    private func touchSession() {
        sessionLastActivity = ProcessInfo.processInfo.systemUptime
    }

    private func lockSessionInternal() {
        sessionGeneration = UUID()
        sessionUnlocked = false
        sessionLastActivity = 0
    }

    private func sendSessionState(_ command: CDVInvokedUrlCommand) {
        let unlocked = isSessionUnlockedInternal()
        var remaining: Double = 0

        if unlocked {
            let elapsedMs =
                (ProcessInfo.processInfo.systemUptime - sessionLastActivity) * 1000

            remaining = max(0, sessionTimeoutMs - elapsedMs)
        }

        sendObject(command, [
            "unlocked": unlocked,
            "timeoutMs": Int(sessionTimeoutMs),
            "lockOnBackground": sessionLockOnBackground,
            "remainingMs": Int(remaining)
        ])
    }

    // MARK: - Biometric helpers

    private struct PromptOptions {
        let title: String
        let reason: String
    }

    private func promptOptions(_ object: Any?) -> PromptOptions {
        guard let dict = object as? [String: Any] else {
            return PromptOptions(
                title: "Unlock secure data",
                reason: "Authenticate to access protected secure data"
            )
        }

        return PromptOptions(
            title: dict["title"] as? String ?? "Unlock secure data",
            reason: dict["reason"] as? String ??
                "Authenticate to access protected secure data"
        )
    }

    // Carry the authenticated LAContext into Keychain access. Dispatch completion
    // to the main queue so callers can safely continue UI-related work.
    private func authenticateBiometrics(
        _ reason: String,
        completion: @escaping (LAContext, Error?) -> Void
    ) {
        let context = LAContext()

        context.localizedCancelTitle = "Cancel"

        var error: NSError?

        guard context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        ) else {
            completion(context, error ?? NSError(
                domain: "UltraSecureStorage",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey:
                    "Biometric authentication is unavailable."]
            ))
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        ) { success, evalError in
            DispatchQueue.main.async {
                if success {
                    completion(context, nil)
                } else {
                    completion(context, evalError ?? NSError(
                        domain: "UltraSecureStorage",
                        code: -2,
                        userInfo: [NSLocalizedDescriptionKey:
                            "Biometric authentication failed."]
                    ))
                }
            }
        }
    }

    // Existence checks do not show a prompt. InteractionNotAllowed can indicate
    // a protected item exists; it does not mean an authorized read succeeded.
    private func biometricItemExists(_ key: String) -> Bool {
        var query = baseQuery(key: key, service: v2Service)

        query[kSecUseAuthenticationUI as String] =
            kSecUseAuthenticationUIFail
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        let status = SecItemCopyMatching(query as CFDictionary, nil)

        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    private func replaceBiometricItem(
        key: String,
        data: Data,
        context: LAContext
    ) throws {
        SecItemDelete(baseQuery(key: key, service: v2Service) as CFDictionary)

        var cfError: Unmanaged<CFError>?

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            &cfError
        ) else {
            throw cfError?.takeRetainedValue() ??
                NSError(domain: "UltraSecureStorage", code: -3,
                        userInfo: [NSLocalizedDescriptionKey:
                            "Unable to create biometric Keychain access control."])
        }

        var query = baseQuery(key: key, service: v2Service)

        query[kSecValueData as String] = data
        query[kSecAttrAccessControl as String] = access
        query[kSecUseAuthenticationContext as String] = context

        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw KeychainError.status(status)
        }
    }

    private func readBiometricItem(key: String, context: LAContext) throws -> String {
        var query = baseQuery(key: key, service: v2Service)

        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            throw KeychainError.status(status)
        }

        guard
            let data = result as? Data,
            let value = String(data: data, encoding: .utf8)
        else {
            throw KeychainError.invalidData
        }

        return value
    }

    // MARK: - Generic Keychain helpers

    private func setKeychainItem(
        _ command: CDVInvokedUrlCommand,
        service: String,
        accessibility: CFString
    ) {
        guard
            let key = command.argument(at: 0) as? String,
            let value = command.argument(at: 1) as? String
        else {
            sendError(command, code: "INVALID_ARGUMENT",
                      message: "set() requires key and value strings.")
            return
        }

        do {
            try validateKey(key)
            let data = try validateAndEncodeValue(value)

            var query = baseQuery(key: key, service: service)
            let update: [String: Any] = [kSecValueData as String: data]

            // Try updating the existing item first. Only ItemNotFound permits insertion;
            // other failures must propagate rather than silently replacing the record.
            let updateStatus = SecItemUpdate(
                query as CFDictionary,
                update as CFDictionary
            )

            if updateStatus == errSecSuccess {
                sendSuccess(command)
                return
            }

            // UPSERT FAILURE RULE
            // Only a missing record justifies adding a new item. Permission, accessibility
            // or other Keychain failures are not evidence that the record is absent.
            // Propagating them preserves the original record and lets JS report the real
            // operation failure. Do not implement recovery by deleting first: a subsequent
            // failed add would turn an update failure into data loss.
            if updateStatus != errSecItemNotFound {
                throw KeychainError.status(updateStatus)
            }

            query[kSecValueData as String] = data
            // Apply the version-specific accessibility policy when creating an item.
            // Changing this policy affects when protected data can be read on the device.
            query[kSecAttrAccessible as String] = accessibility

            let addStatus = SecItemAdd(query as CFDictionary, nil)

            guard addStatus == errSecSuccess else {
                throw KeychainError.status(addStatus)
            }

            sendSuccess(command)
        } catch {
            sendCaughtError(command, code: "SET_FAILED", error: error)
        }
    }

    private func getKeychainItem(
        _ command: CDVInvokedUrlCommand,
        service: String
    ) {
        guard let key = command.argument(at: 0) as? String else {
            sendError(command, code: "INVALID_ARGUMENT",
                      message: "get() requires a key string.")
            return
        }

        do {
            try validateKey(key)

            var query = baseQuery(key: key, service: service)

            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne

            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)

            // Missing data is a distinct API failure. Preserve NOT_FOUND so the JS layer
            // can distinguish absence from denied access or corrupted Keychain data.
            if status == errSecItemNotFound {
                sendError(command, code: "NOT_FOUND", message: "Key does not exists!")
                return
            }

            guard status == errSecSuccess else {
                throw KeychainError.status(status)
            }

            guard
                let data = result as? Data,
                let value = String(data: data, encoding: .utf8)
            else {
                throw KeychainError.invalidData
            }

            let resultPlugin = CDVPluginResult(
                status: CDVCommandStatus_OK,
                messageAs: value
            )

            commandDelegate.send(resultPlugin, callbackId: command.callbackId)
        } catch {
            sendCaughtError(command, code: "GET_FAILED", error: error)
        }
    }

    private func removeKeychainItem(
        _ command: CDVInvokedUrlCommand,
        service: String
    ) {
        guard let key = command.argument(at: 0) as? String else {
            sendError(command, code: "INVALID_ARGUMENT",
                      message: "remove() requires a key string.")
            return
        }

        do {
            try validateKey(key)
            let status = SecItemDelete(
                baseQuery(key: key, service: service) as CFDictionary
            )

            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError.status(status)
            }

            sendSuccess(command)
        } catch {
            sendCaughtError(command, code: "REMOVE_FAILED", error: error)
        }
    }

    private func clearKeychain(
        _ command: CDVInvokedUrlCommand,
        service: String
    ) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            sendError(command, code: "CLEAR_FAILED", message: keychainMessage(status))
            return
        }

        sendSuccess(command)
    }

    private func hasKeychainItem(
        _ command: CDVInvokedUrlCommand,
        service: String
    ) {
        guard let key = command.argument(at: 0) as? String else {
            sendError(command, code: "INVALID_ARGUMENT",
                      message: "has() requires a key string.")
            return
        }

        do {
            try validateKey(key)

            var query = baseQuery(key: key, service: service)

            query[kSecMatchLimit as String] = kSecMatchLimitOne

            let status = SecItemCopyMatching(query as CFDictionary, nil)

            if status == errSecSuccess {
                sendBool(command, value: true)
                return
            }

            if status == errSecItemNotFound {
                sendBool(command, value: false)
                return
            }

            throw KeychainError.status(status)
        } catch {
            sendCaughtError(command, code: "HAS_FAILED", error: error)
        }
    }

    // service + account identify a Keychain item. Changing service names affects
    // existing record visibility and requires considering data migration.
    // WHY A HETEROGENEOUS QUERY DICTIONARY
    // Security.framework expects CFDictionary containing strings, booleans, Data and
    // access-control objects; [String: Any] mirrors that framework boundary.
    // It does not justify merging arbitrary JS properties into native queries.
    // Validated keys and fixed native fields define service/account record identity.
    // Keychain accessibility and access controls enforce OS access, not the dictionary
    // itself. Service changes affect which records are visible and need migration review.
    private func baseQuery(key: String, service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
    }

    // MARK: - Validation / Cordova result helpers

    private func validateKey(_ key: String) throws {
        guard !key.isEmpty else {
            throw ValidationError.invalidKey("Key must be a non-empty string.")
        }

        guard key.count <= maxKeyLength else {
            throw ValidationError.invalidKey("Key exceeds maximum supported length.")
        }
    }

    private func validateAndEncodeValue(_ value: String) throws -> Data {
        guard let data = value.data(using: .utf8) else {
            throw ValidationError.invalidValue(
                "Value could not be encoded as UTF-8."
            )
        }

        guard data.count <= maxValueBytes else {
            throw ValidationError.invalidValue(
                "Value exceeds 64 KiB secure storage limit."
            )
        }

        return data
    }

    private func sendSuccess(_ command: CDVInvokedUrlCommand) {
        let result = CDVPluginResult(status: CDVCommandStatus_OK)

        commandDelegate.send(result, callbackId: command.callbackId)
    }

    private func sendBool(_ command: CDVInvokedUrlCommand, value: Bool) {
        let result = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAs: value
        )

        commandDelegate.send(result, callbackId: command.callbackId)
    }

    private func sendObject(_ command: CDVInvokedUrlCommand, _ value: [String: Any]) {
        let result = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAs: value
        )

        commandDelegate.send(result, callbackId: command.callbackId)
    }

    private func sendCaughtError(
        _ command: CDVInvokedUrlCommand,
        code: String,
        error: Error
    ) {
        let message: String

        switch error {
        case let ValidationError.invalidKey(text):
            message = text
        case let ValidationError.invalidValue(text):
            message = text
        case let KeychainError.status(status):
            if status == errSecItemNotFound && code.contains("GET") {
                sendError(command, code: "NOT_FOUND", message: "Key does not exists!")
                return
            }

            message = keychainMessage(status)
        case KeychainError.invalidData:
            message = "Stored Keychain value is not valid UTF-8 data."
        default:
            message = error.localizedDescription
        }

        sendError(command, code: code, message: message)
    }

    private func sendError(
        _ command: CDVInvokedUrlCommand,
        code: String,
        message: String
    ) {
        let payload: [String: Any] = [
            "code": code,
            "message": message
        ]

        let result = CDVPluginResult(
            status: CDVCommandStatus_ERROR,
            messageAs: payload
        )

        commandDelegate.send(result, callbackId: command.callbackId)
    }

    private func keychainMessage(_ status: OSStatus) -> String {
        if let message = SecCopyErrorMessageString(status, nil) {
            return message as String
        }

        return "Keychain error \(status)."
    }

    private enum ValidationError: Error {
        case invalidKey(String)
        case invalidValue(String)
    }

    private enum KeychainError: Error {
        case status(OSStatus)
        case invalidData
    }
}
