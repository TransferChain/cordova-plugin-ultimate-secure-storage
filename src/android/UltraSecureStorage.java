package com.transferchain.securestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class UltraSecureStorage extends CordovaPlugin {

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int MAX_KEY_LENGTH = 1024;
    private static final int MAX_VALUE_BYTES = 64 * 1024;

    // V1
    private static final String V1_PREFS = "transferchain_secure_storage_v1";
    private static final String V1_ALIAS = "transferchain_secure_storage_master_key_v1";

    // V2
    private static final String V2_PREFS = "transferchain_secure_storage_biometric_v2";
    private static final String V2_ALIAS = "transferchain_secure_storage_biometric_key_v2";

    // V3
    private static final String V3_PREFS = "transferchain_secure_storage_session_v3";
    private static final String V3_ALIAS = "transferchain_secure_storage_session_key_v3";

    private final SecureRandom secureRandom = new SecureRandom();

    // ATOMIC PROMPT ADMISSION
    // compareAndSet combines checking and claiming the interactive prompt slot.
    // A plain check followed by assignment would allow two callers to both pass.
    // Terminal prompt paths release the slot; merely returning from the scheduling
    // method is too early because the UI operation is still pending.
    // This guard protects prompt admission, not the whole database or KDF execution.
    // Independent KDF jobs follow a different concurrency policy.
    private final AtomicBoolean biometricBusy = new AtomicBoolean(false);

    // V3 session state is memory-only by design.
    // VISIBILITY IS NOT TRANSACTIONAL STATE
    // volatile makes individual field updates visible between lifecycle and worker
    // threads. long stores monotonic milliseconds without int-sized uptime overflow.
    // The authorization state is memory-only so plugin restart begins locked.
    // However, checking several volatile fields and updating the idle clock is not
    // one atomic transaction. These fields are not a lock or a general guarantee
    // against compound state races. New transitions need explicit coordination.
    // A background lock does not retroactively cancel an operation already started.
    private volatile boolean sessionUnlocked = false;
    private volatile long sessionLastActivityElapsedMs = 0L;
    private volatile long sessionTimeoutMs = 5 * 60 * 1000L;
    private volatile boolean sessionLockOnBackground = true;
    private long sessionGeneration = 0L;

    @Override
    protected void pluginInitialize() {
        lockSessionInternal();
    }

    @Override
    public void onPause(boolean multitasking) {
        if (sessionLockOnBackground) {
            lockSessionInternal();
        }
    }

    @Override
    public void onReset() {
        lockSessionInternal();
    }

    @Override
    public void onDestroy() {
        lockSessionInternal();
    }

    @Override
    // Preserve the V1/V2/V3 boundaries when dispatching actions. V2 binds its
    // cipher to a biometric prompt; V3 also checks the application session state.
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext)
            throws JSONException {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            sendError(callbackContext, "UNSUPPORTED_ANDROID_VERSION",
                    "Android API 23 or newer is required.");
            return true;
        }

        switch (action) {
            // V1
            case "set":
                runWorker(() -> handleSet(V1_PREFS, V1_ALIAS, args, callbackContext));
                return true;
            case "get":
                runWorker(() -> handleGet(V1_PREFS, V1_ALIAS, args, callbackContext));
                return true;
            case "remove":
                runWorker(() -> handleRemove(V1_PREFS, args, callbackContext));
                return true;
            case "clear":
                runWorker(() -> handleClear(V1_PREFS, callbackContext));
                return true;
            case "has":
                runWorker(() -> handleHas(V1_PREFS, args, callbackContext));
                return true;

            // V2
            case "biometricStatus":
                handleBiometricStatus(callbackContext);
                return true;
            case "setBiometric":
                handleSetBiometric(args, callbackContext);
                return true;
            case "getBiometric":
                handleGetBiometric(args, callbackContext);
                return true;
            case "removeBiometric":
                runWorker(() -> handleRemove(V2_PREFS, args, callbackContext));
                return true;
            case "clearBiometric":
                runWorker(() -> handleClearBiometric(callbackContext));
                return true;
            case "hasBiometric":
                runWorker(() -> handleHas(V2_PREFS, args, callbackContext));
                return true;

            // V3
            case "configureSession":
                handleConfigureSession(args, callbackContext);
                return true;
            case "unlockSession":
                handleUnlockSession(args, callbackContext);
                return true;
            case "lockSession":
                lockSessionInternal();
                sendSessionState(callbackContext);
                return true;
            case "sessionState":
                sendSessionState(callbackContext);
                return true;
            case "setSession":
                runWorker(() -> handleSessionSet(args, callbackContext));
                return true;
            case "getSession":
                runWorker(() -> handleSessionGet(args, callbackContext));
                return true;
            case "removeSession":
                runWorker(() -> handleSessionRemove(args, callbackContext));
                return true;
            case "clearSession":
                runWorker(() -> handleSessionClear(callbackContext));
                return true;
            case "hasSession":
                runWorker(() -> handleSessionHas(args, callbackContext));
                return true;

            default:
                return false;
        }
    }

    // ---------------------------------------------------------------------
    // V1 generic encrypted storage
    // ---------------------------------------------------------------------

    private void handleSet(String prefsName, String alias, JSONArray args, CallbackContext cb) {
        try {
            String key = args.getString(0);
            String value = args.getString(1);

            validateKey(key);
            validateValue(value);

            // RECORD IDENTITY AND ENCRYPTED PAYLOAD
            // The logical key is converted to the persistent storage identifier. Encryption
            // binds its payload to that identifier as GCM AAD, so moving ciphertext to another
            // record name does not create a valid value for that record.
            //
            // The identifier is deterministic so reads can locate the record again; hashing
            // an identifier is not encryption of the identifier or a password KDF. The value
            // is protected separately by a Keystore-backed AES key and a fresh GCM IV.
            String storageKey = deriveStorageKey(key);
            String encrypted = encrypt(alias, storageKey, value, false);

            // Persist the encrypted envelope, never the plaintext value. commit provides
            // a success result, so JS is acknowledged only after persistence succeeds.
            boolean ok = getPreferences(prefsName).edit()
                    .putString(storageKey, encrypted)
                    .commit();

            if (!ok) {
                sendError(cb, "WRITE_FAILED", "Encrypted value could not be persisted.");
                return;
            }

            cb.success();
        } catch (Exception e) {
            sendException(cb, "SET_FAILED", e);
        }
    }

    private void handleGet(String prefsName, String alias, JSONArray args, CallbackContext cb) {
        try {
            String key = args.getString(0);

            validateKey(key);
            String storageKey = deriveStorageKey(key);
            String encrypted = getPreferences(prefsName).getString(storageKey, null);

            if (encrypted == null) {
                sendError(cb, "NOT_FOUND", "Key does not exists!");
                return;
            }

            cb.success(decrypt(alias, storageKey, encrypted, false));
        } catch (Exception e) {
            sendException(cb, "GET_FAILED", e);
        }
    }

    private void handleRemove(String prefsName, JSONArray args, CallbackContext cb) {
        try {
            String key = args.getString(0);

            validateKey(key);
            boolean ok = getPreferences(prefsName).edit()
                    .remove(deriveStorageKey(key))
                    .commit();

            if (!ok) {
                sendError(cb, "REMOVE_FAILED", "Value could not be removed.");
                return;
            }

            cb.success();
        } catch (Exception e) {
            sendException(cb, "REMOVE_FAILED", e);
        }
    }

    private void handleClear(String prefsName, CallbackContext cb) {
        try {
            boolean ok = getPreferences(prefsName).edit().clear().commit();

            if (!ok) {
                sendError(cb, "CLEAR_FAILED", "Secure storage could not be cleared.");
                return;
            }

            cb.success();
        } catch (Exception e) {
            sendException(cb, "CLEAR_FAILED", e);
        }
    }

    private void handleHas(String prefsName, JSONArray args, CallbackContext cb) {
        try {
            String key = args.getString(0);

            validateKey(key);
            sendBoolean(cb, getPreferences(prefsName).contains(deriveStorageKey(key)));
        } catch (Exception e) {
            sendException(cb, "HAS_FAILED", e);
        }
    }

    // ---------------------------------------------------------------------
    // V2 biometric-protected storage
    // ---------------------------------------------------------------------

    private void handleBiometricStatus(CallbackContext cb) {
        try {
            BiometricManager manager = BiometricManager.from(cordova.getContext());
            int result = manager.canAuthenticate(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG
            );

            JSONObject json = new JSONObject();

            json.put("available", result == BiometricManager.BIOMETRIC_SUCCESS);
            json.put("strong", result == BiometricManager.BIOMETRIC_SUCCESS);
            json.put("type", "unknown");
            json.put("code", result);
            cb.success(json);
        } catch (Exception e) {
            sendException(cb, "BIOMETRIC_STATUS_FAILED", e);
        }
    }

    private void handleClearBiometric(CallbackContext cb) {
        try {
            boolean ok = getPreferences(V2_PREFS).edit().clear().commit();

            if (!ok) {
                sendError(cb, "CLEAR_FAILED",
                        "Biometric secure storage could not be cleared.");
                return;
            }

            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);

            keyStore.load(null);

            if (keyStore.containsAlias(V2_ALIAS)) {
                keyStore.deleteEntry(V2_ALIAS);
            }

            cb.success();
        } catch (Exception e) {
            sendException(cb, "BIOMETRIC_CLEAR_FAILED", e);
        }
    }

    private void handleSetBiometric(JSONArray args, CallbackContext cb) {
        try {
            String key = args.getString(0);
            String value = args.getString(1);
            JSONObject prompt = args.optJSONObject(2);

            validateKey(key);
            validateValue(value);
            requireStrongBiometric(cb);

            final String storageKey = deriveStorageKey(key);
            final SecretKey secretKey = getOrCreateKey(V2_ALIAS, true);
            final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, secureRandom);
            cipher.updateAAD(storageKey.getBytes(StandardCharsets.UTF_8));

            showBiometricPrompt(prompt, cipher, cb, authenticatedCipher -> {
                try {
                    byte[] ciphertext = authenticatedCipher.doFinal(
                            value.getBytes(StandardCharsets.UTF_8)
                    );

                    // PERSISTENT ENVELOPE VS CORDOVA BINARY TRANSPORT
                    // Base64 stores IV/ciphertext inside a string-backed JSON preference record;
                    // it is not encryption. The value is encrypted before persistence, and the key
                    // remains under its Keystore alias rather than inside the envelope.
                    // This storage encoding is separate from the crypto plugins' binary bridge.
                    // Malformed envelopes must fail rather than downgrade algorithms. Changing
                    // version/field encoding also requires accounting for already persisted records.
                    JSONObject payload = new JSONObject();

                    payload.put("v", 2);
                    payload.put("iv", Base64.encodeToString(
                            authenticatedCipher.getIV(), Base64.NO_WRAP));
                    payload.put("ct", Base64.encodeToString(
                            ciphertext, Base64.NO_WRAP));

                    boolean ok = getPreferences(V2_PREFS).edit()
                            .putString(storageKey, payload.toString())
                            .commit();

                    if (!ok) {
                        sendError(cb, "WRITE_FAILED",
                                "Biometric-protected value could not be persisted.");
                        return;
                    }

                    cb.success();
                } catch (Exception e) {
                    sendException(cb, "BIOMETRIC_SET_FAILED", e);
                }
            });
        } catch (KeyPermanentlyInvalidatedException e) {
            sendException(cb, "BIOMETRIC_KEY_INVALIDATED", e);
        } catch (Exception e) {
            sendException(cb, "BIOMETRIC_SET_FAILED", e);
        }
    }

    private void handleGetBiometric(JSONArray args, CallbackContext cb) {
        try {
            String key = args.getString(0);
            JSONObject prompt = args.optJSONObject(1);

            validateKey(key);
            requireStrongBiometric(cb);

            final String storageKey = deriveStorageKey(key);
            final String encrypted = getPreferences(V2_PREFS).getString(storageKey, null);

            if (encrypted == null) {
                sendError(cb, "NOT_FOUND", "Key does not exists!");
                return;
            }

            JSONObject payload = new JSONObject(encrypted);

            if (payload.getInt("v") != 2) {
                throw new IllegalStateException("Unsupported biometric payload version.");
            }

            byte[] iv = Base64.decode(payload.getString("iv"), Base64.NO_WRAP);
            byte[] ciphertext = Base64.decode(payload.getString("ct"), Base64.NO_WRAP);

            SecretKey secretKey = getOrCreateKey(V2_ALIAS, true);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

            cipher.init(Cipher.DECRYPT_MODE, secretKey,
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            cipher.updateAAD(storageKey.getBytes(StandardCharsets.UTF_8));

            showBiometricPrompt(prompt, cipher, cb, authenticatedCipher -> {
                try {
                    byte[] plaintext = authenticatedCipher.doFinal(ciphertext);

                    cb.success(new String(plaintext, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    sendException(cb, "BIOMETRIC_GET_FAILED", e);
                }
            });
        } catch (KeyPermanentlyInvalidatedException e) {
            sendException(cb, "BIOMETRIC_KEY_INVALIDATED", e);
        } catch (Exception e) {
            sendException(cb, "BIOMETRIC_GET_FAILED", e);
        }
    }

    private void requireStrongBiometric(CallbackContext cb) throws Exception {
        int status = BiometricManager.from(cordova.getContext()).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
        );

        if (status != BiometricManager.BIOMETRIC_SUCCESS) {
            throw new IllegalStateException(
                    "Strong biometric authentication is unavailable. Code: " + status
            );
        }
    }

    private interface AuthenticatedCipherCallback {
        void run(Cipher cipher);
    }

    private void showBiometricPrompt(
            JSONObject options,
            Cipher cipher,
            CallbackContext cb,
            AuthenticatedCipherCallback onSuccess
    ) {
        // This guard prevents overlapping biometric prompts, not parallel KDF work.
        // Every terminal prompt path must release it so the user can try again.
        if (!biometricBusy.compareAndSet(false, true)) {
            sendError(cb, "BIOMETRIC_BUSY", "Another biometric operation is already active.");
            return;
        }

        // BIOMETRIC UI HANDOFF
        // The prompt must be created on the activity's UI thread. Its asynchronous result
        // continues the pending Cordova operation, so capture only the state needed for
        // that operation and ensure terminal callbacks release the biometric busy guard.
        //
        // A failed fingerprint attempt may leave the prompt open; it is not necessarily
        // a terminal authentication error. Success must use the CryptoObject returned
        // by the prompt, which ties authorization to the specific Keystore operation.
        cordova.getActivity().runOnUiThread(() -> {
            try {
                if (!(cordova.getActivity() instanceof FragmentActivity)) {
                    biometricBusy.set(false);
                    sendError(cb, "BIOMETRIC_HOST_UNSUPPORTED",
                            "Host activity must extend FragmentActivity/AppCompatActivity.");
                    return;
                }

                FragmentActivity activity = (FragmentActivity) cordova.getActivity();
                Executor executor = androidx.core.content.ContextCompat.getMainExecutor(activity);

                BiometricPrompt.AuthenticationCallback authCallback =
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override
                            public void onAuthenticationSucceeded(
                                    @NonNull BiometricPrompt.AuthenticationResult result) {
                                biometricBusy.set(false);
                                BiometricPrompt.CryptoObject crypto = result.getCryptoObject();
                                if (crypto == null || crypto.getCipher() == null) {
                                    sendError(cb, "BIOMETRIC_CRYPTO_MISSING",
                                            "Biometric authentication returned no cipher.");
                                    return;
                                }

                                // Continue with the authenticated CryptoObject cipher. Creating a new cipher
                                // here would lose the operation authorized by the biometric prompt.
                                onSuccess.run(crypto.getCipher());
                            }

                            @Override
                            public void onAuthenticationError(
                                    int errorCode, @NonNull CharSequence errString) {
                                biometricBusy.set(false);
                                sendError(cb, "BIOMETRIC_AUTH_ERROR",
                                        errorCode + ": " + errString);
                            }

                            @Override
                            public void onAuthenticationFailed() {
                                // Non-terminal. Prompt remains active.
                            }
                        };

                BiometricPrompt biometricPrompt =
                        new BiometricPrompt(activity, executor, authCallback);

                String title = options != null
                        ? options.optString("title", "Unlock secure data")
                        : "Unlock secure data";
                String reason = options != null
                        ? options.optString("reason",
                        "Authenticate to access protected secure data")
                        : "Authenticate to access protected secure data";

                BiometricPrompt.PromptInfo promptInfo =
                        new BiometricPrompt.PromptInfo.Builder()
                                .setTitle(title)
                                .setSubtitle(reason)
                                .setAllowedAuthenticators(
                                        BiometricManager.Authenticators.BIOMETRIC_STRONG)
                                .setNegativeButtonText("Cancel")
                                .build();

                biometricPrompt.authenticate(
                        promptInfo,
                        new BiometricPrompt.CryptoObject(cipher)
                );
            } catch (Exception e) {
                biometricBusy.set(false);
                sendException(cb, "BIOMETRIC_PROMPT_FAILED", e);
            }
        });
    }

    private void showBiometricSessionPrompt(JSONObject options, CallbackContext cb) {
        final long generation;

        synchronized (this) {
            generation = sessionGeneration;
        }

        try {
            requireStrongBiometric(cb);

            SecretKey key = getOrCreateKey(V2_ALIAS, true);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

            cipher.init(Cipher.ENCRYPT_MODE, key, secureRandom);

            showBiometricPrompt(options, cipher, cb, authenticatedCipher -> {
                try {
                    // Cryptographic proof-of-use. Output is intentionally discarded.
                    byte[] challenge = new byte[32];

                    byte[] proof = null;

                    try {
                        secureRandom.nextBytes(challenge);
                        proof = authenticatedCipher.doFinal(challenge);
                    } finally {
                        java.util.Arrays.fill(challenge, (byte) 0);
                        if (proof != null) java.util.Arrays.fill(proof, (byte) 0);
                    }

                    completeSessionUnlock(generation, cb);
                } catch (Exception e) {
                    synchronized (this) {
                        if (generation == sessionGeneration) lockSessionInternal();
                    }

                    sendException(cb, "SESSION_UNLOCK_FAILED", e);
                }
            });
        } catch (Exception e) {
            synchronized (this) {
                if (generation == sessionGeneration) lockSessionInternal();
            }

            sendException(cb, "SESSION_UNLOCK_FAILED", e);
        }
    }

    // ---------------------------------------------------------------------
    // V3 native session lock
    // ---------------------------------------------------------------------

    private synchronized void completeSessionUnlock(long generation, CallbackContext cb) {
        // Only the authenticated callback reaches this private commit point.
        // Revocation and publication share a monitor so a stale proof cannot win.
        if (generation != sessionGeneration) {
            sendError(cb, "SESSION_LOCKED", "Secure session is locked.");
            return;
        }

        sessionUnlocked = true;
        touchSession();
        sendSessionState(cb);
    }

    private void handleConfigureSession(JSONArray args, CallbackContext cb) {
        try {
            JSONObject options = args.optJSONObject(0);

            if (options != null) {
                long timeout = options.optLong("timeoutMs", 5 * 60 * 1000L);

                sessionTimeoutMs = Math.max(1000L, timeout);
                sessionLockOnBackground = options.optBoolean("lockOnBackground", true);
            }

            sendSessionState(cb);
        } catch (Exception e) {
            sendException(cb, "SESSION_CONFIG_FAILED", e);
        }
    }

    private void handleUnlockSession(JSONArray args, CallbackContext cb) {
        JSONObject prompt = args.optJSONObject(0);

        showBiometricSessionPrompt(prompt, cb);
    }

    private void handleSessionSet(JSONArray args, CallbackContext cb) {
        if (!requireUnlockedSession(cb)) return;

        touchSession();
        handleSet(V3_PREFS, V3_ALIAS, args, cb);
    }

    private void handleSessionGet(JSONArray args, CallbackContext cb) {
        if (!requireUnlockedSession(cb)) return;

        touchSession();
        handleGet(V3_PREFS, V3_ALIAS, args, cb);
    }

    private void handleSessionRemove(JSONArray args, CallbackContext cb) {
        if (!requireUnlockedSession(cb)) return;

        touchSession();
        handleRemove(V3_PREFS, args, cb);
    }

    private void handleSessionClear(CallbackContext cb) {
        if (!requireUnlockedSession(cb)) return;

        touchSession();
        handleClear(V3_PREFS, cb);
    }

    private void handleSessionHas(JSONArray args, CallbackContext cb) {
        if (!requireUnlockedSession(cb)) return;

        touchSession();
        handleHas(V3_PREFS, args, cb);
    }

    private boolean requireUnlockedSession(CallbackContext cb) {
        if (!isSessionUnlockedInternal()) {
            lockSessionInternal();
            sendError(cb, "SESSION_LOCKED", "Secure session is locked.");
            return false;
        }

        return true;
    }

    // Measure idle time with monotonic elapsedRealtime. Wall-clock changes must
    // not extend the session lifetime.
    private boolean isSessionUnlockedInternal() {
        if (!sessionUnlocked) return false;

        long elapsed = SystemClock.elapsedRealtime() - sessionLastActivityElapsedMs;

        if (elapsed >= sessionTimeoutMs) {
            lockSessionInternal();
            return false;
        }

        return true;
    }

    private void touchSession() {
        sessionLastActivityElapsedMs = SystemClock.elapsedRealtime();
    }

    private synchronized void lockSessionInternal() {
        sessionGeneration++;
        sessionUnlocked = false;
        sessionLastActivityElapsedMs = 0L;
    }

    private void sendSessionState(CallbackContext cb) {
        try {
            boolean unlocked = isSessionUnlockedInternal();
            long remaining = 0L;

            if (unlocked) {
                long elapsed = SystemClock.elapsedRealtime() - sessionLastActivityElapsedMs;

                remaining = Math.max(0L, sessionTimeoutMs - elapsed);
            }

            JSONObject json = new JSONObject();

            json.put("unlocked", unlocked);
            json.put("timeoutMs", sessionTimeoutMs);
            json.put("lockOnBackground", sessionLockOnBackground);
            json.put("remainingMs", remaining);
            cb.success(json);
        } catch (Exception e) {
            sendException(cb, "SESSION_STATE_FAILED", e);
        }
    }

    // ---------------------------------------------------------------------
    // Crypto helpers
    // ---------------------------------------------------------------------

    // GCM generates a fresh IV; AAD binds the payload to storageKey. Moving an
    // encrypted payload to another key must not pass authentication.
    private String encrypt(String alias, String storageKey, String plaintext, boolean authRequired)
            throws Exception {
        SecretKey secretKey = getOrCreateKey(alias, authRequired);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, secureRandom);
        cipher.updateAAD(storageKey.getBytes(StandardCharsets.UTF_8));

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        JSONObject payload = new JSONObject();

        payload.put("v", 1);
        payload.put("iv", Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP));
        payload.put("ct", Base64.encodeToString(ciphertext, Base64.NO_WRAP));
        return payload.toString();
    }

    private String decrypt(String alias, String storageKey, String encrypted, boolean authRequired)
            throws Exception {
        JSONObject payload = new JSONObject(encrypted);

        if (payload.getInt("v") != 1) {
            throw new IllegalStateException("Unsupported secure storage payload version.");
        }

        byte[] iv = Base64.decode(payload.getString("iv"), Base64.NO_WRAP);
        byte[] ciphertext = Base64.decode(payload.getString("ct"), Base64.NO_WRAP);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(alias, authRequired),
                new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        cipher.updateAAD(storageKey.getBytes(StandardCharsets.UTF_8));

        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    // Synchronize competing key creation for an alias. Keys remain in Keystore;
    // do not merge V2 per-operation authentication settings with V1/V3 policies.
    private synchronized SecretKey getOrCreateKey(String alias, boolean biometricRequired)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);

        keyStore.load(null);

        if (!keyStore.containsAlias(alias)) {
            KeyGenerator generator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    ANDROID_KEY_STORE
            );

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true);

            if (biometricRequired) {
                builder.setUserAuthenticationRequired(true);

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // A zero validity interval requires authentication for each key operation.
                    // Do not replace it with the V3 application-session idle timeout.
                    builder.setUserAuthenticationParameters(
                            0,
                            KeyProperties.AUTH_BIOMETRIC_STRONG
                    );
                } else {
                    builder.setUserAuthenticationValidityDurationSeconds(-1);
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        builder.setInvalidatedByBiometricEnrollment(true);
                    }
                }
            }

            generator.init(builder.build(), secureRandom);
            generator.generateKey();
        }

        SecretKey key = (SecretKey) keyStore.getKey(alias, null);

        if (key == null) {
            throw new IllegalStateException("Android Keystore key is unavailable: " + alias);
        }

        return key;
    }

    private SharedPreferences getPreferences(String name) {
        return cordova.getActivity()
                .getApplicationContext()
                .getSharedPreferences(name, Context.MODE_PRIVATE);
    }

    private String deriveStorageKey(String logicalKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] hash = digest.digest(logicalKey.getBytes(StandardCharsets.UTF_8));

        return Base64.encodeToString(
                hash,
                Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING
        );
    }

    private void validateKey(String key) {
        if (key == null || key.length() == 0) {
            throw new IllegalArgumentException("Key must be a non-empty string.");
        }

        if (key.length() > MAX_KEY_LENGTH) {
            throw new IllegalArgumentException("Key exceeds maximum supported length.");
        }
    }

    private void validateValue(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Value must not be null.");
        }

        int bytes = value.getBytes(StandardCharsets.UTF_8).length;

        if (bytes > MAX_VALUE_BYTES) {
            throw new IllegalArgumentException("Value exceeds 64 KiB secure storage limit.");
        }
    }

    private void runWorker(Runnable runnable) {
        cordova.getThreadPool().execute(runnable);
    }

    private void sendBoolean(CallbackContext cb, boolean value) {
        cb.sendPluginResult(new PluginResult(PluginResult.Status.OK, value));
    }

    private void sendException(CallbackContext cb, String code, Exception e) {
        String message = e.getMessage();

        if (message == null || message.length() == 0) {
            message = e.getClass().getSimpleName();
        }

        sendError(cb, code, message);
    }

    private void sendError(CallbackContext cb, String code, String message) {
        JSONObject error = new JSONObject();

        try {
            error.put("code", code);
            error.put("message", message);
            cb.error(error);
        } catch (JSONException ignored) {
            cb.error(code + ": " + message);
        }
    }
}
