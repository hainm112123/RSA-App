# RSA Core Implementation Documentation

This document explains the technical details of the pure-Python RSA implementation used in the RSA Learning Lab.

## 1. Mathematical Foundation
The core of RSA is based on the difficulty of factoring the product of two large prime numbers.

### Key Generation
1. **Prime Selection**: Two large prime numbers, $p$ and $q$, are generated using a cryptographically secure random source and verified with the **Miller-Rabin Primality Test**.
2. **Modulus ($n$)**: $n = p \times q$. This value is used as the modulus for both public and private keys.
3. **Totient ($\phi$)**: $\phi(n) = (p-1)(q-1)$.
4. **Public Exponent ($e$)**: A value (usually $65537$) such that $1 < e < \phi(n)$ and $gcd(e, \phi(n)) = 1$.
5. **Private Exponent ($d$)**: The modular multiplicative inverse of $e$ modulo $\phi(n)$, calculated using the **Extended Euclidean Algorithm**.

## 2. Encryption & Padding (OAEP)
To prevent mathematical attacks and ensure that the same message produces different ciphertexts (semantic security), we use **Optimal Asymmetric Encryption Padding (OAEP)**.

### The OAEP Process:
1. **Hashing**: The implementation uses **SHA-256** as the primary hash function.
2. **MGF1 (Mask Generation Function)**: A deterministic function that expands a small seed into a large mask of a specified length.
3. **Structure**:
   - The message is padded with a hash of the label and a separator byte.
   - A random **seed** is generated.
   - The seed masks the data block, and the data block masks the seed.
4. **Numerical Conversion**: The resulting byte array is converted into a large integer using `int.from_bytes(..., 'big')`.
5. **Modular Exponentiation**: $c = m^e \pmod n$.

## 3. Digital Signatures
The lab uses a scheme inspired by PKCS#1 v1.5 for pedagogical clarity.

1. **Hashing**: The message is hashed using **SHA-256**.
2. **Padding**: The hash is prepended with a specific padding string (`RSA-LAB-SHA256|`) and a series of `0xFF` bytes to fill the RSA block size.
3. **Signing**: The padded block is raised to the power of the private exponent: $s = m^d \pmod n$.
4. **Verification**: The verifier raises the signature to the public exponent $e$ and checks if the resulting block matches the expected hash and padding structure.

## 4. Implementation Details
- **Arbitrary Precision**: The implementation leverages Python's native support for arbitrarily large integers.
*   **Efficiency**: Modular exponentiation is performed using Python's built-in `pow(m, e, n)`, which is highly optimized for large numbers.
- **Security**: The `secrets` module is used for all random number generation to ensure cryptographic strength.

---
*Note: This implementation is for educational purposes. For production environments, use standard libraries like OpenSSL or Python's `cryptography` package.*
