package com.arpan.pqc.classic;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public final class RsaDemo {
    private RsaDemo() {
    }

    public static void runSingle() throws Exception {
        System.out.println("RSA-OAEP (key transport) and RSA-PSS (signature) demo");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // OAEP encryption of a random 32-byte blob
        Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        oaep.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] blob = new byte[32];
        new SecureRandom().nextBytes(blob);
        byte[] c = oaep.doFinal(blob);

        oaep.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] back = oaep.doFinal(c);

        // PSS signature
        Signature pss = Signature.getInstance("RSASSA-PSS");
        pss.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        pss.initSign(kp.getPrivate());
        byte[] msg = "hello rsa".getBytes();
        pss.update(msg);
        byte[] sig = pss.sign();

        Signature ver = Signature.getInstance("RSASSA-PSS");
        ver.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        ver.initVerify(kp.getPublic());
        ver.update(msg);
        boolean ok = ver.verify(sig);

        System.out.printf("  OAEP ct=%d bytes, PSS sig=%d bytes, verify=%b | WARNING: vulnerable to Shor in future%n",
                c.length, sig.length, ok);
    }
}
