import XCTest
import UIKit
import Cordova
import CryptoTestSupport
@testable import NativeCryptoPlugins

// Only synthetic, uniquely named records are touched. No clear-all action is used.
final class SecureStoragePluginTests: XCTestCase {
    private func invoke(_ plugin: UltraSecureStorage, _ action: String, _ args: [Any]) throws -> CDVPluginResult {
        let done = expectation(description: action)
        done.assertForOverFulfill = true
        let delegate = CryptoTestDelegate()
        var captured: CDVPluginResult?
        delegate.onResult = { result in captured = result; done.fulfill() }
        plugin.commandDelegate = delegate
        let command = CDVInvokedUrlCommand(arguments: args, callbackId: "test-storage",
            className: "UltraSecureStorage", methodName: action)
        _ = plugin.perform(NSSelectorFromString(action + ":"), with: command)
        wait(for: [done], timeout: 10)
        return try XCTUnwrap(captured)
    }

    private func ok(_ plugin: UltraSecureStorage, _ action: String, _ args: [Any]) throws -> CDVPluginResult {
        let result = try invoke(plugin, action, args)
        XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_OK.rawValue))
        return result
    }

    private func reject(_ plugin: UltraSecureStorage, _ action: String, _ args: [Any], _ code: String) throws {
        let result = try invoke(plugin, action, args)
        XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_ERROR.rawValue))
        let error = try XCTUnwrap(result.message as? [String: Any])
        XCTAssertEqual(error["code"] as? String, code)
    }

    func testV1RoundtripOverwriteMissingAndNamespaceIsolation() throws {
        let plugin = UltraSecureStorage()
        let key = "native-test-" + UUID().uuidString
        defer { _ = try? ok(plugin, "remove", [key]) }
        try reject(plugin, "get", [key], "NOT_FOUND")
        _ = try ok(plugin, "set", [key, "synthetic-one"])
        XCTAssertEqual(try ok(plugin, "get", [key]).message as? String, "synthetic-one")
        _ = try ok(plugin, "set", [key, "synthetic-two"])
        XCTAssertEqual(try ok(plugin, "get", [key]).message as? String, "synthetic-two")
        XCTAssertEqual(try ok(plugin, "hasBiometric", [key]).message as? Bool, false)
        try reject(plugin, "getSession", [key], "SESSION_LOCKED")
        _ = try ok(plugin, "remove", [key])
        try reject(plugin, "get", [key], "NOT_FOUND")
    }

    func testV2MissingAndInvalidInputWithoutPrompt() throws {
        let plugin = UltraSecureStorage()
        let key = "native-test-" + UUID().uuidString
        defer { _ = try? ok(plugin, "removeBiometric", [key]) }
        XCTAssertEqual(try ok(plugin, "hasBiometric", [key]).message as? Bool, false)
        try reject(plugin, "getBiometric", [key], "NOT_FOUND")
        let invalid = try invoke(plugin, "setBiometric", ["", "synthetic"])
        XCTAssertEqual(invalid.status.intValue, Int(CDVCommandStatus_ERROR.rawValue))
    }

    @MainActor
    func testV3LockedCRUDMinimumTimeoutAndReset() throws {
        let plugin = UltraSecureStorage()
        plugin.pluginInitialize()
        let key = "native-test-" + UUID().uuidString
        let state = try XCTUnwrap(try ok(plugin, "sessionState", []).message as? [String: Any])
        XCTAssertEqual(state["unlocked"] as? Bool, false)
        XCTAssertEqual(state["remainingMs"] as? Int, 0)
        let configured = try XCTUnwrap(try ok(plugin, "configureSession", [["timeoutMs": -1, "lockOnBackground": true]]).message as? [String: Any])
        XCTAssertEqual(configured["timeoutMs"] as? Int, 1000)
        for action in ["getSession", "setSession", "hasSession", "removeSession"] {
            try reject(plugin, action, [key, "synthetic"], "SESSION_LOCKED")
        }
        NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)
        let background = try XCTUnwrap(try ok(plugin, "sessionState", []).message as? [String: Any])
        XCTAssertEqual(background["unlocked"] as? Bool, false)
        plugin.onReset()
        let reset = try XCTUnwrap(try ok(plugin, "sessionState", []).message as? [String: Any])
        XCTAssertEqual(reset["unlocked"] as? Bool, false)
    }

    func testParallelV1DistinctKeys() throws {
        let keys = (0..<4).map { _ in "native-test-" + UUID().uuidString }
        let plugins = keys.map { _ in UltraSecureStorage() }
        let delegates = keys.map { _ in CryptoTestDelegate() }
        defer {
            for index in keys.indices { _ = try? ok(plugins[index], "remove", [keys[index]]) }
        }
        let writes = expectation(description: "parallel unique writes")
        writes.expectedFulfillmentCount = keys.count
        writes.assertForOverFulfill = true
        for index in keys.indices {
            delegates[index].onResult = { result in
                XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_OK.rawValue))
                writes.fulfill()
            }
            plugins[index].commandDelegate = delegates[index]
            let command = try XCTUnwrap(CDVInvokedUrlCommand(arguments: [keys[index], "synthetic-" + String(index)],
                callbackId: "write-" + String(index), className: "UltraSecureStorage", methodName: "set"))
            DispatchQueue.global().async { plugins[index].set(command) }
        }
        wait(for: [writes], timeout: 10)
        for index in keys.indices {
            XCTAssertEqual(try ok(plugins[index], "get", [keys[index]]).message as? String, "synthetic-" + String(index))
        }
        withExtendedLifetime(delegates) {}
    }

    func testInteractiveBiometricSuccessCancelExpiryAndCrossVersionWrites() throws {
        throw XCTSkip("Requires enrolled biometric interactive device harness; no injected unlocked state")
    }
}
