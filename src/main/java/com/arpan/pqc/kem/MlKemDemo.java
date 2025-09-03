package com.arpan.pqc.kem;

import com.arpan.pqc.util.CryptoUtil;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * Demonstrates ML-KEM (Kyber) using the Bouncy Castle KEM API. Generates a keypair,
 * encapsulates a secret to derive an AES-256 key, decrypts it, and uses it to
 * perform AES-GCM encryption/decryption. Prints expected and actual sizes for
 * comparison.
 */
public final class MlKemDemo {
    private MlKemDemo() {
    }

    private static MLKEMParameterSpec specForLevel(int level) {
        switch (level) {
            case 512:
                return MLKEMParameterSpec.ml_kem_512;
            case 768:
                return MLKEMParameterSpec.ml_kem_768;
            case 1024:
                return MLKEMParameterSpec.ml_kem_1024;
            default:
                throw new IllegalArgumentException("Level must be 512, 768 or 1024");
        }
    }

    /**
     * Run a single ML-KEM demo at the default security level (768).
     */
    public static void runSingle() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("ML-KEM (Kyber) demo (AES-GCM via derived secret)");
        encapsDecapsOnce(768);
    }

    /**
     * Generate a key pair at the given security level, perform encapsulation and
     * decapsulation, derive an AES-256 key and run an AES-GCM round-trip.
     *
     * @param level security level (512, 768 or 1024)
     */
    public static void encapsDecapsOnce(int level) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        MLKEMParameterSpec params = specForLevel(level);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(params, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        // Expected sizes from FIPS 203
        int[] ek_dk_ct = (level == 512) ? new int[]{800, 1632, 768}
                : (level == 768) ? new int[]{1184, 2400, 1088}
                : new int[]{1568, 3168, 1568};
        System.out.printf("  Level ML-KEM-%d | Encapsulation key (pk) approx %d bytes, Decapsulation key (sk) approx %d, Ciphertext approx %d%n",
                level, ek_dk_ct[0], ek_dk_ct[1], ek_dk_ct[2]);

        // Sender: derive AES key and encapsulation bytes
        KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "BC");
        SecretKeyWithEncapsulation senderSecret = (SecretKeyWithEncapsulation)
                kg.generateKey(new KEMGenerateSpec(kp.getPublic(), "AES", 256));
        byte[] aesKeySender = senderSecret.getEncoded();
        byte[] encapsulation = senderSecret.getEncapsulation();

        // Receiver: decapsulate using private key
        KeyGenerator kg2 = KeyGenerator.getInstance("ML-KEM", "BC");
        javax.crypto.SecretKey aesKeyReceiver = kg2.generateKey(new KEMExtractSpec(kp.getPrivate(), "AES", 256, encapsulation));
        if (!Arrays.equals(aesKeySender, aesKeyReceiver.getEncoded())) {
            throw new IllegalStateException("KEM secret mismatch!");
        }

        // Use derived key in AES-GCM
        byte[] iv = CryptoUtil.randomBytes(12);
        byte[] pt = "hello pqc".getBytes();
        byte[] ct = CryptoUtil.aesGcmEncrypt(aesKeySender, pt, null, iv);
        byte[] round = CryptoUtil.aesGcmDecrypt(aesKeyReceiver.getEncoded(), ct, null, iv);

        System.out.printf("  AES key size: %d bytes | Encapsulation bytes: %d | Ciphertext (GCM) length: %d | Round-trip ok: %b%n",
                aesKeySender.length, encapsulation.length, ct.length, Arrays.equals(pt, round));
    }
}
