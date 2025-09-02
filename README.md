# PQC Java Demo: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+) + AES/RSA/DES comparison

This repository contains a **Java\u00a017+ Maven** project demonstrating NIST's first standardized post‑quantum cryptography (PQC) algorithms: **ML‑KEM** (Kyber), **ML‑DSA** (Dilithium) and **SLH‑DSA** (SPHINCS+). It also includes classic algorithms (AES‑GCM, RSA‑OAEP/RSASSA‑PSS and DES) for comparison.

## Background

In August 2024 NIST published the first PQC standards: **FIPS 203** (ML‑KEM), **FIPS 204** (ML‑DSA) and **FIPS 205** (SLH‑DSA). These algorithms are designed to resist attacks by quantum computers. For confidentiality, the key encapsulation mechanism ML‑KEM replaces RSA/ECC key exchange; for digital signatures, ML‑DSA and SLH‑DSA replace RSA/ECC signatures. This project uses the Bouncy Castle 1.81 provider to access these algorithms via the Java Cryptography Architecture (JCA).

## Usage

### Requirements

* Java 17 or newer
* Maven 3.8+

### Build and run

```bash
mvn -q -DskipTests package
mvn -q exec:java
```

On execution the program will:

* Generate an ML‑KEM keypair (default: ML‑KEM‑768), derive a 256‑bit AES key using the KEM API, encrypt and decrypt a sample plaintext using AES‑GCM, and verify that round‑trip decryption matches.
* Generate an ML‑DSA‑65 keypair (Dilithium level 3), sign a message and verify the signature.
* Generate an SLH‑DSA keypair (default: `slh_dsa_sha2_128s`), sign a message and verify the signature.
* For comparison, run AES‑256‑GCM symmetric encryption, RSA‑OAEP for key transport with RSA‑PSS signatures, and DES (as an example of a deprecated algorithm).

You can pass `--bench` to the program to run a small benchmark. It will print rough median times for one encapsulation/decapsulation, one signature and one verification. The results will vary between systems and Java versions.

### Project layout

```
pqc-java-all-pqc-demo/
  ├─ pom.xml
  ├─ src/main/java/com/arpan/pqc/
  │    ├─ Main.java       — orchestrates demos
  │    ├─ kem/MlKemDemo.java
  │    ├─ sig/MlDsaDemo.java
  │    ├─ sig/SlhDsaDemo.java
  │    ├─ classic/AesDemo.java
  │    ├─ classic/RsaDemo.java
  │    ├─ classic/DesDemo.java
  │    └─ util/
  │         ├─ CryptoUtil.java
  │         └─ Benchmark.java
  └─ README.md
```

## Sizes and test results

During a sample run on a laptop (Java 17, Bouncy Castle 1.81), the following observations were made:

* **ML‑KEM‑768** (Kyber): public key ≈ 1184 bytes, private key ≈ 2400 bytes, ciphertext ≈ 1088 bytes, shared secret 32 bytes. Deriving and using the key for an AES‑GCM encryption is practically instantaneous (≈1‑2 ms). The encapsulation size is larger than an RSA 2048 key exchange but acceptable for TLS.
* **ML‑DSA‑65** (Dilithium level 3): public key ≈ 1952 bytes, private key ≈ 4032 bytes, signature ≈ 3309 bytes. Signing and verification are fast (≈1‑5 ms), but the signatures are around 3 KB compared with ≈256 bytes for RSA‑2048/PSS.
* **SLH‑DSA** (SPHINCS+) with parameter `slh_dsa_sha2_128s`: public key ≈ 32 bytes, private key ≈ 64 bytes, signature size ≈ 7856 bytes. Signing is slower and signatures are very large, but the scheme is stateless and hash‑based, providing long‑term security.
* **AES‑256‑GCM**: symmetric encryption with a randomly generated 256‑bit key is extremely fast (< 1 ms) and secure against quantum attacks (Grover’s algorithm halves the key strength; using 256‑bit keys compensates).
* **RSA‑2048** (OAEP/PSS): key pair generation, encryption and signature operations are fast on modern hardware, but RSA/ECC are vulnerable to Shor’s algorithm. RSA keys are smaller (2048 bits) and ciphertexts are about 256 bytes.
* **DES**: a 56‑bit symmetric cipher. For historical comparison only; it is deprecated and should never be used in new systems. The block size (64 bits) and key size (56 bits) are insufficient; NIST withdrew SP 800‑67 in 2023.

## Insights: benefits and challenges of PQC

* **Quantum resilience**: ML‑KEM and ML‑DSA are designed to withstand attacks by quantum computers, unlike RSA and ECC. When combined with AES‑256‑GCM, they provide end‑to‑end confidentiality and authenticity in a post‑quantum world.
* **Larger artifacts**: The most noticeable drawback is size. Public keys, private keys, ciphertexts and signatures are often an order of magnitude larger than their classical counterparts. Protocols and certificate formats must be updated to accommodate these sizes, which may affect network latency and storage.
* **Performance**: ML‑KEM and ML‑DSA have performance comparable to or better than RSA‑2048 on modern CPUs. SPHINCS+ (SLH‑DSA) is slower but offers a hash‑based alternative with different security assumptions.
* **Transition**: Modern systems will likely adopt **hybrid** handshakes—combining traditional RSA/ECC with PQC—to ensure interoperability. Libraries such as OpenSSL already support such hybrids. During the transition, careful planning is needed to handle certificate chains, protocol negotiation and hardware security modules.
* **Symmetric crypto remains**: Algorithms like AES and SHA‑2 remain secure if key lengths are doubled. PQC primarily replaces asymmetric primitives for key exchange and signatures.

## References

* NIST FIPS 203 (ML‑KEM)
* NIST FIPS 204 (ML‑DSA)
* NIST FIPS 205 (SLH‑DSA)
* NIST SP 800‑131A (Transitioning the Use of Cryptographic Algorithms and Key Lengths)
* Bouncy Castle 1.81 release notes

This project is for educational and experimental purposes. It should not be used as‑is in production without a thorough security review and updates to depend on the latest PQC standards and provider releases.
