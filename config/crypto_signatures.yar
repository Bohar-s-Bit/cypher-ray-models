/*
 * CypherRay - Cryptographic Signatures YARA Rules
 * Comprehensive YARA rules for detecting cryptographic implementations
 * in compiled binaries across multiple architectures.
 */

rule AES_Constants {
    meta:
        description = "Detects AES S-box and round constants"
        algorithm = "AES"
        severity = "high"
        
    strings:
        // AES S-box first 16 bytes
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
        
        // AES Inverse S-box first 16 bytes
        $inv_sbox = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }
        
        // AES Round constants (Rcon)
        $rcon = { 01 02 04 08 10 20 40 80 1b 36 }
        
        // AES MixColumns matrix
        $mixcol = { 02 03 01 01 01 02 03 01 01 01 02 03 03 01 01 02 }
        
    condition:
        any of them
}

rule ChaCha20_Salsa20_Constants {
    meta:
        description = "Detects ChaCha20/Salsa20 stream cipher constants"
        algorithm = "ChaCha20/Salsa20"
        severity = "high"
        
    strings:
        // "expand 32-byte k" in little-endian
        $chacha_sigma = { 61 70 78 65 33 32 2d 62 79 74 65 20 6b }
        $chacha_expand = "expand 32-byte k"
        
        // "expand 16-byte k" for 128-bit keys
        $chacha_tau = "expand 16-byte k"
        
        // ChaCha20 quarter-round constant positions
        $quarter_round = { 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        
    condition:
        any of them
}

rule SHA256_Constants {
    meta:
        description = "Detects SHA-256 initialization vectors and round constants"
        algorithm = "SHA-256"
        severity = "high"
        
    strings:
        // SHA-256 initial hash values (H0-H7) - little endian
        $h0_le = { 67 e6 09 6a }
        $h1_le = { 85 ae 67 bb }
        $h2_le = { 72 f3 6e 3c }
        $h3_le = { 3a f5 4f a5 }
        
        // SHA-256 initial hash values - big endian
        $h0_be = { 6a 09 e6 67 }
        $h1_be = { bb 67 ae 85 }
        
        // SHA-256 K constants (first few)
        $k0 = { 98 2f 8a 42 }
        $k1 = { 91 44 37 71 }
        $k2 = { cf fb c0 b5 }
        
    condition:
        2 of them
}

rule SHA1_Constants {
    meta:
        description = "Detects SHA-1 initialization vectors"
        algorithm = "SHA-1"
        severity = "medium"
        
    strings:
        // SHA-1 initial hash values
        $h0 = { 01 23 45 67 }
        $h1 = { 89 ab cd ef }
        $h2 = { fe dc ba 98 }
        $h3 = { 76 54 32 10 }
        $h4 = { f0 e1 d2 c3 }
        
    condition:
        3 of them
}

rule MD5_Constants {
    meta:
        description = "Detects MD5 initialization constants"
        algorithm = "MD5"
        severity = "medium"
        
    strings:
        // MD5 initial values (A, B, C, D)
        $md5_a = { 01 23 45 67 }
        $md5_b = { 89 ab cd ef }
        $md5_c = { fe dc ba 98 }
        $md5_d = { 76 54 32 10 }
        
        // MD5 sine table constants (first few)
        $md5_t1 = { d7 6a a4 78 }
        $md5_t2 = { e8 c7 b7 56 }
        
    condition:
        3 of them
}

rule DES_3DES_Constants {
    meta:
        description = "Detects DES/3DES permutation tables and S-boxes"
        algorithm = "DES/3DES"
        severity = "medium"
        
    strings:
        // DES Initial Permutation (IP) table start
        $ip_table = { 3a 32 2a 22 1a 12 0a 02 }
        
        // DES S-box 1 (first row)
        $sbox1 = { 0e 04 0d 01 02 0f 0b 08 }
        
        // DES PC-1 table
        $pc1_table = { 39 31 29 21 19 11 09 01 }
        
        // DES Expansion table
        $expansion = { 20 01 02 03 04 05 04 05 }
        
    condition:
        any of them
}

rule RSA_ECC_Primes {
    meta:
        description = "Detects well-known RSA/ECC curve parameters"
        algorithm = "RSA/ECC"
        severity = "high"
        
    strings:
        // SECP256K1 (Bitcoin curve) - suffix of prime
        $secp256k1_p = { ff ff ff fe ff ff fc 2f }
        
        // SECP256K1 order (n) suffix
        $secp256k1_n = { d0 36 41 41 }
        
        // P-256 (NIST) prime suffix
        $p256_prime = { ff ff ff ff 00 00 00 01 }
        
        // Common RSA modulus patterns (2048-bit)
        $rsa_modulus = { 00 [127] 00 }
        
    condition:
        any of them
}

rule BLAKE2_Constants {
    meta:
        description = "Detects BLAKE2 hash function constants"
        algorithm = "BLAKE2"
        severity = "high"
        
    strings:
        // BLAKE2b IV (first constant)
        $blake2b_iv0 = { 08 c9 bc f3 67 e6 09 6a }
        
        // BLAKE2s IV (first constant)
        $blake2s_iv0 = { 67 e6 09 6a }
        
        // BLAKE2 sigma permutations
        $blake2_sigma = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
        
    condition:
        any of them
}

rule RC4_Initialization {
    meta:
        description = "Detects RC4 stream cipher initialization patterns"
        algorithm = "RC4"
        severity = "low"
        
    strings:
        // RC4 identity permutation (S-box init)
        $rc4_init = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
        
        // RC4 key scheduling loop pattern (simplified)
        $ksa_pattern = { 00 [255] ff }
        
    condition:
        any of them
}

rule Base64_Encoding {
    meta:
        description = "Detects Base64 encoding tables"
        algorithm = "Base64"
        severity = "low"
        
    strings:
        // Standard Base64 alphabet
        $base64_std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        
        // URL-safe Base64 alphabet
        $base64_url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        
    condition:
        any of them
}

rule Cryptographic_XOR_Loops {
    meta:
        description = "Detects XOR encryption/decryption loops (architecture-independent)"
        algorithm = "XOR Cipher"
        severity = "medium"
        
    strings:
        // x86/x64: xor [reg], [reg/mem]; inc/add; loop/jne
        $xor_x86 = { 31 ?? ?? 40 7? ?? }
        $xor_x64 = { 48 31 ?? ?? 48 ff ?? 75 ?? }
        
        // ARM: eor instruction patterns
        $xor_arm = { ?? ?? ?? e0 }
        
        // MIPS: xor instruction
        $xor_mips = { 26 ?? ?? 00 }
        
    condition:
        any of them
}

rule Bit_Rotation_Operations {
    meta:
        description = "Detects bit rotation operations common in crypto algorithms"
        algorithm = "Generic Crypto Operations"
        severity = "low"
        
    strings:
        // x86 ROL/ROR instructions
        $rol_x86 = { c1 c0 }
        $ror_x86 = { c1 c8 }
        
        // x86 shift and or pattern (manual rotation)
        $rotate_pattern = { d3 ?? ?? c3 ?? 09 }
        
    condition:
        any of them
}

rule HMAC_Implementation {
    meta:
        description = "Detects HMAC implementation patterns"
        algorithm = "HMAC"
        severity = "high"
        
    strings:
        // HMAC inner/outer padding constants
        $ipad = { 36 36 36 36 36 36 36 36 }
        $opad = { 5c 5c 5c 5c 5c 5c 5c 5c }
        
    condition:
        all of them
}

rule PBKDF2_KDF {
    meta:
        description = "Detects PBKDF2 key derivation function patterns"
        algorithm = "PBKDF2"
        severity = "high"
        
    strings:
        // PBKDF2 iteration counter (big-endian 1)
        $counter = { 00 00 00 01 }
        
        // Common PBKDF2 strings
        $pbkdf2_str = "PBKDF2" nocase
        $prf_str = "HMAC-SHA" nocase
        
    condition:
        any of them
}

rule Bcrypt_Scrypt_Argon2 {
    meta:
        description = "Detects modern password hashing algorithms"
        algorithm = "Bcrypt/Scrypt/Argon2"
        severity = "high"
        
    strings:
        // Bcrypt signature
        $bcrypt = "$2a$" ascii
        $bcrypt_alt = "$2b$" ascii
        
        // Scrypt signature
        $scrypt = "scrypt" nocase
        
        // Argon2 variants
        $argon2i = "$argon2i$" ascii
        $argon2d = "$argon2d$" ascii
        $argon2id = "$argon2id$" ascii
        
    condition:
        any of them
}

rule TLS_SSL_Handshake {
    meta:
        description = "Detects TLS/SSL handshake constants and strings"
        algorithm = "TLS/SSL"
        severity = "high"
        
    strings:
        // TLS version strings
        $tls12 = { 03 03 }  // TLS 1.2
        $tls13 = { 03 04 }  // TLS 1.3
        
        // Handshake message types
        $client_hello = { 01 00 00 }
        $server_hello = { 02 00 00 }
        
        // Common cipher suite identifiers
        $tls_aes_gcm = { 13 01 }  // TLS_AES_128_GCM_SHA256
        $tls_chacha = { 13 03 }   // TLS_CHACHA20_POLY1305_SHA256
        
    condition:
        any of them
}

rule Poly1305_MAC {
    meta:
        description = "Detects Poly1305 MAC algorithm"
        algorithm = "Poly1305"
        severity = "high"
        
    strings:
        // Poly1305 prime (2^130 - 5) in various forms
        $poly_prime = { fb ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff }
        
        // Poly1305 clamp mask
        $poly_clamp = { 0f ff ff fc 0f ff ff fc 0f ff ff fc 0f ff ff fc }
        
    condition:
        any of them
}

rule Curve25519_Ed25519 {
    meta:
        description = "Detects Curve25519/Ed25519 elliptic curve crypto"
        algorithm = "Curve25519/Ed25519"
        severity = "high"
        
    strings:
        // Curve25519 prime (2^255 - 19)
        $curve25519_p = { ed ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff }
        
        // Ed25519 base point Y coordinate
        $ed25519_base = { 58 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
        
    condition:
        any of them
}

rule High_Entropy_Data_Block {
    meta:
        description = "Detects high-entropy data blocks (potential crypto keys/tables)"
        algorithm = "Generic"
        severity = "low"
        
    strings:
        // Look for blocks of seemingly random data (256+ bytes)
        $high_entropy = /[\x00-\xFF]{256,}/ 
        
    condition:
        #high_entropy > 5
}
