package com.arpan.pqc;

import com.arpan.pqc.classic.AesDemo;
import com.arpan.pqc.classic.DesDemo;
import com.arpan.pqc.classic.RsaDemo;
import com.arpan.pqc.kem.MlKemDemo;
import com.arpan.pqc.sig.MlDsaDemo;
import com.arpan.pqc.sig.SlhDsaDemo;
import com.arpan.pqc.util.Benchmark;

/**
 * Entry point for the PQC demo. Runs KEM and signature demos as well as classic
 * algorithms for comparison. Pass --bench to run a simple benchmark.
 */
public class Main {
    public static void main(String[] args) throws Exception {
        boolean bench = false;
        for (String a : args) {
            if ("--bench".equals(a)) {
                bench = true;
            }
        }

        System.out.println("=== PQC Java Demo (ML-KEM, ML-DSA, SLH-DSA) ===");
        System.out.println();

        MlKemDemo.runSingle();
        MlDsaDemo.runSingle();
        SlhDsaDemo.runSingle();

        System.out.println();
        System.out.println("=== Classic algorithms (contrast) ===");
        AesDemo.runSingle();
        RsaDemo.runSingle();
        DesDemo.runSingle();

        if (bench) {
            System.out.println();
            System.out.println("=== Benchmark (coarse, wall-clock) ===");
            Benchmark.runAll();
        }
    }
}
