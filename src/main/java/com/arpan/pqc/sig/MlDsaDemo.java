package com.arpan.pqc.sig;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * Demonstrates ML-DSA (Dilithium) signatures. Generates a key pair for a given
 * security category, signs a message and verifies it, printing the sizes of
 * the public key and signature.
 */
public final class MlDsaDemo {
    private MlDsaDemo() {
    }

    private static MLDSAParameterSpec specForLevel(int level) {
        switch (level) {
            case 44:
                return MLDSAParameterSpec.ml_dsa_44;
            case 65:
                return MLDSAParameterSpec.ml_dsa_65;
            case 87:
                return MLDSAParameterSpec.ml_dsa_87;
            default:
                throw new IllegalArgumentException("Level must be 44, 65 or 87");
        }
    }

    /**
     * Run a single ML-DSA demo at the default level (65).
     */
    public static void runSingle() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("ML-DSA (Dilithium) signature demo");
        signVerifyOnce(65);
    }

    /**
     * Generate a key pair and perform a sign/verify round-trip.
     *
     * @param level Dilithium level (44, 65, 87)
     */
    public static void signVerifyOnce(int level) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(specForLevel(level), new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA", "BC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        byte[] msg = "hello pqc sig".getBytes();
        sig.update(msg);
        byte[] s = sig.sign();

        Signature ver = Signature.getInstance("ML-DSA", "BC");
        ver.initVerify(kp.getPublic());
        ver.update(msg);
        boolean ok = ver.verify(s);

        System.out.printf("  ML-DSA-%d | pub=%d bytes, sig=%d bytes | verify=%b%n",
                level, kp.getPublic().getEncoded().length, s.length, ok);
    }
}
