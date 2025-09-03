package com.arpan.pqc.util;

import com.arpan.pqc.kem.MlKemDemo;
import com.arpan.pqc.sig.MlDsaDemo;
import com.arpan.pqc.sig.SlhDsaDemo;
import org.json.JSONObject;

/**
 * Simple benchmarking harness. Uses wall clock time to measure the median
 * duration (in nanoseconds) of a few operations. Not a rigorous micro-benchmark
 * but sufficient for comparing rough performance characteristics.
 */
public final class Benchmark {
    private Benchmark() {
    }

    private static long[] times(Runnable r, int rounds) {
        long[] t = new long[rounds];
        for (int i = 0; i < rounds; i++) {
            long s = System.nanoTime();
            r.run();
            t[i] = System.nanoTime() - s;
        }
        java.util.Arrays.sort(t);
        return t;
    }

    private static long median(long[] ts) {
        int n = ts.length;
        return (n % 2 == 1) ? ts[n / 2] : ((ts[n / 2 - 1] + ts[n / 2]) / 2);
    }

    /**
     * Run a few benchmark operations and print the results as a JSON object.
     */
    public static void runAll() {
        int N = 5;
        JSONObject out = new JSONObject();
        out.put("mlkem768_encaps_ns_med", median(times(() -> {
            try {
                MlKemDemo.encapsDecapsOnce(768);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, N)));
        out.put("mldsa65_sign_ns_med", median(times(() -> {
            try {
                MlDsaDemo.signVerifyOnce(65);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, N)));
        out.put("slhdsa_128s_sign_ns_med", median(times(() -> {
            try {
                SlhDsaDemo.signVerifyOnce("slh_dsa_sha2_128s");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, N)));
        System.out.println(out.toString(2));
    }
}
