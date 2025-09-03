package com.arpan.pqc.sig;

import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

public final class SlhDsaDemo {
    private SlhDsaDemo() {
    }

    private static SLHDSAParameterSpec specForName(String name) {
        switch (name) {
            case "slh_dsa_sha2_128s":
                return SLHDSAParameterSpec.slh_dsa_sha2_128s;
            case "slh_dsa_sha2_128f":
                return SLHDSAParameterSpec.slh_dsa_sha2_128f;
            case "slh_dsa_sha2_192s":
                return SLHDSAParameterSpec.slh_dsa_sha2_192s;
            case "slh_dsa_sha2_192f":
                return SLHDSAParameterSpec.slh_dsa_sha2_192f;
            case "slh_dsa_sha2_256s":
                return SLHDSAParameterSpec.slh_dsa_sha2_256s;
            case "slh_dsa_sha2_256f":
                return SLHDSAParameterSpec.slh_dsa_sha2_256f;
            default:
                return SLHDSAParameterSpec.slh_dsa_sha2_128s;
        }
    }

    public static void runSingle() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("SLH-DSA (SPHINCS+) signature demo");
        signVerifyOnce("slh_dsa_sha2_128s");
    }

    public static void signVerifyOnce(String paramName) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SLHDSAParameterSpec params = specForName(paramName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        kpg.initialize(params, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SLH-DSA", "BC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        byte[] msg = "hello slh-dsa".getBytes();
        sig.update(msg);
        byte[] s = sig.sign();

        Signature ver = Signature.getInstance("SLH-DSA", "BC");
        ver.initVerify(kp.getPublic());
        ver.update(msg);
        boolean ok = ver.verify(s);

        System.out.printf("  %s | pub=%d bytes, sig=%d bytes | verify=%b%n",
                paramName, kp.getPublic().getEncoded().length, s.length, ok);
    }
}
