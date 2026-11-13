package com.droidscope.secure;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Recommended cryptography: AES-GCM, generated keys, per-message nonces. */
public final class CryptoUtil {

    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_BYTES = 12;

    private CryptoUtil() {}

    /** Keys are generated at runtime, never embedded in the application. */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    /** Authenticated encryption with a fresh random nonce for every message. */
    public static byte[] encrypt(SecretKey key, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[NONCE_BYTES];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return cipher.doFinal(plaintext);
    }

    /** A cryptographically secure generator, unseeded so the platform seeds it. */
    public static String secureRandomToken() {
        byte[] buffer = new byte[32];
        new SecureRandom().nextBytes(buffer);
        StringBuilder builder = new StringBuilder();
        for (byte b : buffer) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
}
