package com.arpan.pqc.classic;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Arrays;

public class DesDemo {
    public static void main(String[] args) throws Exception {
        // Generate 3DES key
        KeyGenerator kg = KeyGenerator.getInstance("DESede");
        kg.init(168);
        SecretKey key = kg.generateKey();

        byte[] pt = "Hello World".getBytes();

        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = cipher.doFinal(pt);

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] back = cipher.doFinal(ct);

        System.out.printf(
                "DESede (3DES) example: pt=%d bytes, ct=%d bytes, ok=%b | WARNING: deprecated due to small block size and meet-in-the-middle attacks\n",
                pt.length, ct.length, Arrays.equals(pt, back)
        );
    }
}
