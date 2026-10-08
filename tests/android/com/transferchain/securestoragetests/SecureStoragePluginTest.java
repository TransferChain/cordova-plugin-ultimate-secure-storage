package com.transferchain.securestoragetests;

import android.content.Context;
import android.content.Intent;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.transferchain.securestorage.UltraSecureStorage;
import java.util.UUID;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import org.junit.Ignore;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaPreferences;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class SecureStoragePluginTest {
    private ExecutorService pool;
    private TestCordova cordova;

    @Before public void setUp() {
        pool = Executors.newFixedThreadPool(2);
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> cordova = new TestCordova(pool));
    }

    @After public void tearDown() throws Exception {
        pool.shutdown();
        assertTrue("Native work did not finish", pool.awaitTermination(60, TimeUnit.SECONDS));
    }

    private PluginResult call(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        // Initialize each storage instance once; lifecycle tests reuse its state.
        if (plugin.cordova == null) plugin.privateInitialize("test", cordova, null, new CordovaPreferences());
        Capture callback = new Capture();
        assertTrue(plugin.execute(action, args, callback));
        assertTrue("Native callback timed out", callback.done.await(60, TimeUnit.SECONDS));
        assertEquals(1, callback.count);
        return callback.result;
    }

    private PluginResult ok(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        PluginResult result = call(plugin, action, args);
        assertEquals("Native operation rejected", PluginResult.Status.OK.ordinal(), result.getStatus());
        return result;
    }

    private void rejects(CordovaPlugin plugin, String action, JSONArray args, String code) throws Exception {
        PluginResult result = call(plugin, action, args);
        assertEquals(PluginResult.Status.ERROR.ordinal(), result.getStatus());
        JSONObject error = new JSONObject(result.getMessage());
        assertEquals(code, error.getString("code"));
        assertFalse(error.getString("message").isEmpty());
    }

    private static String uniqueKey() { return "native-test-" + UUID.randomUUID(); }
    private static boolean flag(PluginResult result) { return Boolean.parseBoolean(result.getMessage()); }
    private static String text(PluginResult result) throws Exception {
        return new JSONArray("[" + result.getMessage() + "]").getString(0);
    }

    @Test public void v1RoundtripOverwriteMissingAndNamespaceIsolation() throws Exception {
        UltraSecureStorage plugin = new UltraSecureStorage();
        String key = uniqueKey();
        try {
            rejects(plugin, "get", new JSONArray().put(key), "NOT_FOUND");
            assertFalse(flag(ok(plugin, "has", new JSONArray().put(key))));
            ok(plugin, "set", new JSONArray().put(key).put("synthetic-one"));
            assertEquals("synthetic-one", text(ok(plugin, "get", new JSONArray().put(key))));
            ok(plugin, "set", new JSONArray().put(key).put("synthetic-two"));
            assertEquals("synthetic-two", text(ok(plugin, "get", new JSONArray().put(key))));
            assertFalse(flag(ok(plugin, "hasBiometric", new JSONArray().put(key))));
            rejects(plugin, "getSession", new JSONArray().put(key), "SESSION_LOCKED");
            ok(plugin, "remove", new JSONArray().put(key));
            rejects(plugin, "get", new JSONArray().put(key), "NOT_FOUND");
        } finally { ok(plugin, "remove", new JSONArray().put(key)); plugin.onDestroy(); }
    }

    @Test public void v2MissingAndInvalidInputsNeverNeedBiometricPrompt() throws Exception {
        UltraSecureStorage plugin = new UltraSecureStorage();
        String key = uniqueKey();
        try {
            assertFalse(flag(ok(plugin, "hasBiometric", new JSONArray().put(key))));
            PluginResult missing = call(plugin, "getBiometric", new JSONArray().put(key));
            assertEquals(PluginResult.Status.ERROR.ordinal(), missing.getStatus());
            String code = new JSONObject(missing.getMessage()).getString("code");
            int capability = BiometricManager.from(cordova.getContext()).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG);
            assertEquals(capability == BiometricManager.BIOMETRIC_SUCCESS
                ? "NOT_FOUND" : "BIOMETRIC_GET_FAILED", code);
            if (capability != BiometricManager.BIOMETRIC_SUCCESS) {
                assertEquals("Strong biometric authentication is unavailable. Code: " + capability,
                    new JSONObject(missing.getMessage()).getString("message"));
            }
            rejects(plugin, "setBiometric", new JSONArray().put("").put("synthetic"), "BIOMETRIC_SET_FAILED");
        } finally { ok(plugin, "removeBiometric", new JSONArray().put(key)); plugin.onDestroy(); }
    }

    @Test public void v3StartsLockedClampsMinimumAndLocksOnLifecycle() throws Exception {
        UltraSecureStorage plugin = new UltraSecureStorage();
        String key = uniqueKey();
        JSONObject state = new JSONObject(ok(plugin, "sessionState", new JSONArray()).getMessage());
        assertFalse(state.getBoolean("unlocked"));
        assertEquals(0, state.getLong("remainingMs"));
        state = new JSONObject(ok(plugin, "configureSession", new JSONArray().put(
            new JSONObject().put("timeoutMs", -1).put("lockOnBackground", true))).getMessage());
        assertEquals(1000, state.getLong("timeoutMs"));
        for (String action : new String[] {"getSession", "setSession", "hasSession", "removeSession"}) {
            rejects(plugin, action, new JSONArray().put(key).put("synthetic"), "SESSION_LOCKED");
        }
        plugin.onPause(false);
        plugin.onReset();
        assertFalse(new JSONObject(ok(plugin, "sessionState", new JSONArray()).getMessage()).getBoolean("unlocked"));
        plugin.onDestroy();
    }

    @Test public void v1ParallelDistinctKeysDoNotMixValues() throws Exception {
        UltraSecureStorage plugin = new UltraSecureStorage();
        ok(plugin, "sessionState", new JSONArray());
        ExecutorService callers = Executors.newFixedThreadPool(2);
        List<String> keys = new ArrayList<>();
        List<Future<?>> work = new ArrayList<>();
        try {
            for (int index = 0; index < 4; index++) {
                String key = uniqueKey(), value = "synthetic-" + index;
                keys.add(key);
                work.add(callers.submit(() -> {
                    ok(plugin, "set", new JSONArray().put(key).put(value));
                    assertEquals(value, text(ok(plugin, "get", new JSONArray().put(key))));
                    return null;
                }));
            }
            for (Future<?> task : work) task.get(30, TimeUnit.SECONDS);
        } finally {
            callers.shutdown();
            assertTrue(callers.awaitTermination(30, TimeUnit.SECONDS));
            for (String key : keys) ok(plugin, "remove", new JSONArray().put(key));
            plugin.onDestroy();
        }
    }

    // Read-only reflection verifies revocation fencing, not biometric authorization.
    private static long generation(UltraSecureStorage plugin) throws Exception {
        java.lang.reflect.Field field = UltraSecureStorage.class.getDeclaredField("sessionGeneration");
        field.setAccessible(true);
        return field.getLong(plugin);
    }

    @Test public void lockResetAndPauseAdvanceRevocationGeneration() throws Exception {
        UltraSecureStorage plugin = new UltraSecureStorage();
        ok(plugin, "sessionState", new JSONArray());
        long before = generation(plugin);
        ok(plugin, "lockSession", new JSONArray());
        assertTrue(generation(plugin) > before);
        before = generation(plugin);
        plugin.onReset();
        assertTrue(generation(plugin) > before);
        before = generation(plugin);
        plugin.onPause(false);
        assertTrue(generation(plugin) > before);
        plugin.onDestroy();
    }

    @Test public void staleBiometricCompletionCannotUnlockAfterRevocation() throws Exception {
        UltraSecureStorage plugin = new UltraSecureStorage();
        ok(plugin, "sessionState", new JSONArray());
        java.lang.reflect.Method complete = UltraSecureStorage.class.getDeclaredMethod(
            "completeSessionUnlock", long.class, CallbackContext.class);
        complete.setAccessible(true);
        try {
            for (int action = 0; action < 3; action++) {
                long stale = generation(plugin);
                if (action == 0) ok(plugin, "lockSession", new JSONArray());
                else if (action == 1) plugin.onReset();
                else plugin.onPause(false);
                assertTrue(generation(plugin) > stale);
                Capture callback = new Capture();
                // A revoked proof only: never invoke the current-generation success path.
                complete.invoke(plugin, stale, callback);
                assertTrue(callback.done.await(5, TimeUnit.SECONDS));
                assertEquals(1, callback.count);
                assertEquals(PluginResult.Status.ERROR.ordinal(), callback.result.getStatus());
                assertEquals("SESSION_LOCKED", new JSONObject(callback.result.getMessage()).getString("code"));
                assertFalse(new JSONObject(ok(plugin, "sessionState", new JSONArray()).getMessage()).getBoolean("unlocked"));
            }
        } finally { plugin.onDestroy(); }
    }

    @Ignore("Requires enrolled biometric interactive harness; never inject unlocked state")
    @Test public void enrolledUnlockCancelIdleExpiryAndCrossVersionWrites() {
        throw new AssertionError("Run the explicit biometric device procedure before enabling this case");
    }

    private static class Capture extends CallbackContext {
        final CountDownLatch done = new CountDownLatch(1);
        volatile PluginResult result;
        volatile int count;
        Capture() { super("test", null); }
        @Override public synchronized void sendPluginResult(PluginResult value) {
            result = value;
            count++;
            done.countDown();
        }
    }

    // Noninteractive context host only; this never attaches a window or runs app auth.
    // Biometric prompt success/cancellation still requires the separate device procedure.
    private static class TestActivity extends AppCompatActivity {
        @Override public Context getApplicationContext() {
            return InstrumentationRegistry.getInstrumentation().getTargetContext().getApplicationContext();
        }
    }

    private static class TestCordova implements CordovaInterface {
        final AppCompatActivity activity = new TestActivity();
        final ExecutorService executor;
        TestCordova(ExecutorService executor) { this.executor = executor; }
        @Override public ExecutorService getThreadPool() { return executor; }
        @Override public Context getContext() { return InstrumentationRegistry.getInstrumentation().getTargetContext(); }
        @Override public AppCompatActivity getActivity() { return activity; }
        @Override public void startActivityForResult(CordovaPlugin plugin, Intent intent, int code) { throw new UnsupportedOperationException(); }
        @Override public void setActivityResultCallback(CordovaPlugin plugin) { throw new UnsupportedOperationException(); }
        @Override public Object onMessage(String id, Object data) { return null; }
        @Override public void requestPermission(CordovaPlugin plugin, int code, String permission) { throw new UnsupportedOperationException(); }
        @Override public void requestPermissions(CordovaPlugin plugin, int code, String[] permissions) { throw new UnsupportedOperationException(); }
        @Override public boolean hasPermission(String permission) { return true; }
    }
}
