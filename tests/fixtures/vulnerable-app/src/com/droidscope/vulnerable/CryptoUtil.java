package com.droidscope.vulnerable;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** DroidScope fixture: deliberately weak cryptography. */
public final class CryptoUtil {

    // DS-CRYPTO-009: hardcoded symmetric key material
    private static final String ENCRYPTION_KEY = "Sup3rS3cr3tK3y16";
    private static final byte[] STATIC_IV = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    private CryptoUtil() {}

    /** DS-CRYPTO-001: password hashed with MD5. */
    public static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hashed = digest.digest(password.getBytes("UTF-8"));
            StringBuilder builder = new StringBuilder();
            for (byte b : hashed) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /** DS-CRYPTO-003: obsolete DES cipher. */
    public static byte[] encryptLegacy(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes("UTF-8"), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /** DS-CRYPTO-004: AES in ECB mode. */
    public static byte[] encryptEcb(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /** DS-CRYPTO-005: fixed initialisation vector. */
    public static byte[] encryptCbc(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(STATIC_IV));
        return cipher.doFinal(data);
    }

    /** DS-CRYPTO-006: predictable generator used for a session token. */
    public static String generateToken() {
        Random random = new Random(System.currentTimeMillis());
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            token.append(Integer.toHexString(random.nextInt(16)));
        }
        return token.toString();
    }

    /** DS-CRYPTO-008: RSA without OAEP padding. */
    public static Cipher rsaCipher() throws Exception {
        return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    /** Correct usage: must NOT be reported. */
    public static byte[] secureRandomBytes() {
        byte[] buffer = new byte[32];
        new SecureRandom().nextBytes(buffer);
        return buffer;
    }

    /** Correct usage: MD5 for a cache key must NOT be reported by DS-CRYPTO-001. */
    public static String cacheKeyFor(String url) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            return new String(digest.digest(url.getBytes("UTF-8")));
        } catch (Exception e) {
            return url;
        }
    }
}
