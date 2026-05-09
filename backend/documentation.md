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

## 3. Digital Signatures (PSS)
The lab uses **Probabilistic Signature Scheme (PSS)**, which is the modern standard for RSA signatures.

1. **Hashing**: The message is hashed using **SHA-256** to produce $mHash$.
2. **Salt**: A random **salt** (equal to the hash size) is generated, making the signature probabilistic (different every time).
3. **MGF1**: A mask is generated from the hash $H$ (which is a hash of the original $mHash$ combined with the salt) and applied to the data block.
4. **Structure**: The resulting block ($EM$) contains the masked salt, the hash $H$, and a trailer byte (`0xBC`).
5. **Signing**: The encoded block is raised to the power of the private exponent: $s = m^d \pmod n$.
6. **Verification**: The verifier uses the public key to recover the encoded block, extracts the salt using MGF1, and reconstructs $H$ to verify the signature's integrity and authenticity.

## 4. Implementation Details
- **Arbitrary Precision**: The implementation leverages Python's native support for arbitrarily large integers.
*   **Efficiency**: Modular exponentiation is performed using Python's built-in `pow(m, e, n)`, which is highly optimized for large numbers.
- **Security**: The `secrets` module is used for all random number generation to ensure cryptographic strength.

---
*Note: This implementation is for educational purposes. For production environments, use standard libraries like OpenSSL or Python's `cryptography` package.*
