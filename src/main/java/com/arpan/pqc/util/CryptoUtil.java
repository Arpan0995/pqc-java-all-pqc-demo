package com.arpan.pqc.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility functions for crypto operations used in the demos. Provides helpers for
 * generating random data, encoding to base64 and performing AES-GCM
 * encryption/decryption. This is not intended to be a general-purpose crypto
 * library.
 */
public final class CryptoUtil {
    private CryptoUtil() {
    }

    /**
     * Generate an array of random bytes.
     *
     * @param n number of bytes
     * @return random byte array
     */
    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    /**
     * Encode bytes into a Base64 string.
     *
     * @param data input bytes
     * @return Base64 encoded string
     */
    public static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Perform AES-GCM encryption.
     *
     * @param key       raw AES key
     * @param plaintext plaintext
     * @param aad       associated data (may be null)
     * @param iv        12-byte initialization vector
     * @return ciphertext with tag appended
     */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] plaintext, byte[] aad, byte[] iv) throws Exception {
        SecretKey sk = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, sk, spec);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(plaintext);
    }

    /**
     * Perform AES-GCM decryption.
     *
     * @param key        raw AES key
     * @param ciphertext ciphertext with tag appended
     * @param aad        associated data (may be null)
     * @param iv         12-byte initialization vector
     * @return plaintext
     */
    public static byte[] aesGcmDecrypt(byte[] key, byte[] ciphertext, byte[] aad, byte[] iv) throws Exception {
        SecretKey sk = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, sk, spec);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ciphertext);
    }

    /**
     * Generate a random AES key of the given length (in bits).
     *
     * @param bits key length (e.g. 128, 192, 256)
     * @return raw key bytes
     */
    public static byte[] randomAesKey(int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(bits);
        SecretKey k = kg.generateKey();
        return k.getEncoded();
    }

    /**
     * Convert a String to UTF-8 bytes.
     *
     * @param s input string
     * @return UTF-8 encoded bytes
     */
    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
