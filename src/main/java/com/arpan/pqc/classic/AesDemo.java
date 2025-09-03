package com.arpan.pqc.classic;

import com.arpan.pqc.util.CryptoUtil;

public final class AesDemo {
    private AesDemo() {
    }

    public static void runSingle() throws Exception {
        System.out.println("AES-256-GCM symmetric demo");
        byte[] key = CryptoUtil.randomAesKey(256);
        byte[] iv = CryptoUtil.randomBytes(12);
        byte[] pt = "hello aes".getBytes();
        byte[] ct = CryptoUtil.aesGcmEncrypt(key, pt, null, iv);
        byte[] round = CryptoUtil.aesGcmDecrypt(key, ct, null, iv);
        System.out.printf("  key=%d bytes, ctLen=%d, roundTrip=%b%n", key.length, ct.length, java.util.Arrays.equals(pt, round));
    }
}
