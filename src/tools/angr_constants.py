"""
Angr tool for detecting known cryptographic constants in binaries.
"""

from typing import Dict, Any

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def angr_detect_crypto_constants(binary_path: str) -> Dict[str, Any]:
    """
    Search for known cryptographic constants in the binary
    (e.g., AES S-box values, SHA round constants, etc.)
    
    Args:
        binary_path: Path to the binary file
        
    Returns:
        Dict containing detected constants or error message
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        project = angr.Project(binary_path, auto_load_libs=False)
        
        # Comprehensive crypto constants database
        crypto_constants = {
            # AES Constants
            "AES_SBOX_FIRST_BYTES": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b]),
            "AES_INV_SBOX_FIRST": bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36]),
            "AES_RCON_FIRST": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20]),
            
            # ChaCha20/Salsa20 Constants
            "CHACHA20_CONSTANT": b"expand 32-byte k",  # 0x61707865...
            "SALSA20_CONSTANT": b"expand 32-byte k",
            "CHACHA20_SIGMA": bytes([0x65, 0x78, 0x70, 0x61, 0x6e, 0x64]),  # "expand"
            
            # SHA Family
            "SHA256_K_FIRST": bytes.fromhex('428a2f98'),
            "SHA256_K_SECOND": bytes.fromhex('71374491'),
            "SHA256_INIT_H0": bytes.fromhex('6a09e667'),
            "SHA1_INIT_H0": bytes.fromhex('67452301'),
            "SHA1_INIT_H1": bytes.fromhex('efcdab89'),
            "SHA512_K_FIRST": bytes.fromhex('428a2f98d728ae22'),
            "SHA512_INIT_H0": bytes.fromhex('6a09e667f3bcc908'),
            
            # MD5
            "MD5_INIT_A": bytes.fromhex('67452301'),
            "MD5_INIT_B": bytes.fromhex('efcdab89'),
            "MD5_INIT_C": bytes.fromhex('98badcfe'),
            
            # DES/3DES
            "DES_IP_TABLE_START": bytes([58, 50, 42, 34, 26, 18]),
            "DES_SBOX1_FIRST": bytes([14, 4, 13, 1, 2, 15]),
            "DES_PC1_TABLE": bytes([57, 49, 41, 33, 25, 17]),
            
            # RSA/ECC Common Primes & Curves
            "SECP256K1_P_SUFFIX": bytes.fromhex('fffffffefffffc2f'),  # Last 8 bytes
            "SECP256K1_N_SUFFIX": bytes.fromhex('d0364141'),
            "P256_PRIME_SUFFIX": bytes.fromhex('ffffffff00000001'),
            
            # BLAKE2
            "BLAKE2B_IV0": bytes.fromhex('6a09e667f3bcc908'),
            "BLAKE2S_IV0": bytes.fromhex('6a09e667'),
            
            # RC4 (identity permutation check)
            "RC4_INIT_PATTERN": bytes(range(16)),  # First 16 bytes of S-box init
            
            # Common Base64 tables
            "BASE64_TABLE": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
        }
        
        detected_constants = []
        
        # Search through binary sections
        for const_name, const_bytes in crypto_constants.items():
            for section_name, section in project.loader.main_object.sections_map.items():
                try:
                    data = project.loader.memory.load(section.vaddr, section.memsize)
                    if const_bytes in data:
                        offset = data.find(const_bytes)
                        detected_constants.append({
                            "constant_name": const_name,
                            "section": section_name,
                            "offset": hex(section.vaddr + offset),
                            "algorithm_hint": _infer_algorithm_from_constant(const_name)
                        })
                except:
                    continue
        
        # Group by algorithm for better presentation
        algorithm_groups = {}
        for const in detected_constants:
            algo = const["algorithm_hint"]
            if algo not in algorithm_groups:
                algorithm_groups[algo] = []
            algorithm_groups[algo].append(const["constant_name"])
        
        return {
            "detected_constants": detected_constants,
            "total_found": len(detected_constants),
            "algorithm_groups": algorithm_groups,
            "confidence_level": _calculate_confidence(algorithm_groups)
        }
    except Exception as e:
        return {"error": f"Failed to detect crypto constants: {str(e)}"}


def _infer_algorithm_from_constant(const_name: str) -> str:
    """Infer algorithm family from constant name"""
    if "AES" in const_name:
        return "AES"
    elif "CHACHA" in const_name or "SALSA" in const_name:
        return "ChaCha20/Salsa20"
    elif "SHA256" in const_name:
        return "SHA-256"
    elif "SHA512" in const_name:
        return "SHA-512"
    elif "SHA1" in const_name:
        return "SHA-1"
    elif "MD5" in const_name:
        return "MD5"
    elif "DES" in const_name:
        return "DES/3DES"
    elif "SECP" in const_name or "P256" in const_name:
        return "ECC"
    elif "BLAKE" in const_name:
        return "BLAKE2"
    elif "RC4" in const_name:
        return "RC4"
    elif "BASE64" in const_name:
        return "Base64"
    return "Unknown"


def _calculate_confidence(algorithm_groups: Dict[str, list]) -> str:
    """Calculate overall confidence based on number of constants found"""
    max_constants = max(len(v) for v in algorithm_groups.values()) if algorithm_groups else 0
    
    if max_constants >= 4:
        return "very_high"
    elif max_constants >= 2:
        return "high"
    elif max_constants >= 1:
        return "medium"
    return "low"


def detect_hardcoded_keys(binary_path: str) -> Dict[str, Any]:
    """
    Detect potential hardcoded cryptographic keys/IVs in binary data sections.
    
    **CRITICAL FIX**: Filters out known cryptographic constants (AES S-Box, SHA IVs, etc.)
    to prevent false positives.
    
    Looks for:
    - Static byte arrays in .rodata, .data sections
    - Common key sizes: 8, 16, 24, 32 bytes (DES, AES-128, 3DES, AES-256)
    - Non-zero, high-entropy patterns that could be keys
    - **Excludes known algorithm constants**
    
    Args:
        binary_path: Path to the binary file
        
    Returns:
        Dict containing detected hardcoded keys (excluding algorithm constants)
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available"}
        
        project = angr.Project(binary_path, auto_load_libs=False)
        hardcoded_keys = []
        
        # Target data sections that typically contain constants
        target_sections = ['.rodata', '__rodata', '.data', '__data', '__const', '.rdata']
        
        for section_name, section in project.loader.main_object.sections_map.items():
            # Only scan data/rodata sections
            if not any(target in section_name.lower() for target in target_sections):
                continue
            
            try:
                data = project.loader.memory.load(section.vaddr, section.memsize)
                
                # Scan for potential keys at different offsets
                for offset in range(0, len(data) - 8):
                    for key_size in [8, 16, 24, 32]:  # Common key sizes
                        if offset + key_size > len(data):
                            continue
                        
                        candidate = data[offset:offset + key_size]
                        
                        # **CRITICAL FILTERS**:
                        # 1. Check if it's a known algorithm constant (AES S-Box, SHA IV, etc.)
                        # 2. Check entropy (reject all-zeros, low-entropy buffers)
                        # 3. Heuristic: non-ASCII, non-repeating pattern
                        
                        if _is_known_crypto_constant(candidate):
                            # This is an algorithm constant (e.g., AES S-Box), not a secret key
                            continue
                        
                        if _is_potential_key(candidate):
                            hardcoded_keys.append({
                                "size_bytes": key_size,
                                "section": section_name,
                                "offset": hex(section.vaddr + offset),
                                "preview": candidate[:8].hex(),  # First 8 bytes
                                "likely_type": _guess_key_type(key_size),
                                "entropy": _calculate_entropy(candidate)
                            })
                            
                            # Skip overlapping candidates
                            offset += key_size - 1
                            break
            except Exception as e:
                continue
        
        # Deduplicate by offset
        seen_offsets = set()
        unique_keys = []
        for key in hardcoded_keys:
            if key["offset"] not in seen_offsets:
                seen_offsets.add(key["offset"])
                unique_keys.append(key)
        
        return {
            "hardcoded_keys": unique_keys[:10],  # Limit to top 10 most likely
            "total_candidates": len(unique_keys),
            "has_hardcoded_keys": len(unique_keys) > 0
        }
    except Exception as e:
        return {"error": f"Failed to detect hardcoded keys: {str(e)}"}


def _is_known_crypto_constant(data: bytes) -> bool:
    """
    **FIX #1: Known Cryptographic Constants Database**
    
    Check if byte sequence matches known algorithm constants (not secret keys).
    
    Returns True if this is a public algorithm constant (AES S-Box, SHA IV, etc.)
    that should NOT be flagged as a hardcoded secret.
    """
    # Database of known public cryptographic constants
    KNOWN_CONSTANTS = {
        # AES S-Box (first 16 bytes are highly distinctive)
        bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
               0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]): "AES S-Box",
        
        # AES Inverse S-Box (first 16 bytes)
        bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
               0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]): "AES Inverse S-Box",
        
        # SHA-256 Initial Hash Values (H0-H7)
        bytes.fromhex('6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19'): "SHA-256 IV",
        
        # SHA-1 Initial Hash Values
        bytes.fromhex('67452301efcdab8998badcfe10325476c3d2e1f0'): "SHA-1 IV",
        
        # MD5 Initial Hash Values
        bytes.fromhex('0123456789abcdeffedcba9876543210'): "MD5 IV",
        
        # ChaCha20/Salsa20 Sigma constant
        b"expand 32-byte k": "ChaCha20/Salsa20 Sigma",
        b"expand 16-byte k": "ChaCha20/Salsa20 Tau",
    }
    
    # Check exact matches (for full constants)
    for known_const, name in KNOWN_CONSTANTS.items():
        if data == known_const:
            return True
        # Check if data contains the known constant
        if len(data) >= len(known_const) and known_const in data:
            return True
    
    # Check partial matches (first N bytes)
    # AES S-Box first 8 bytes (highly distinctive)
    if data[:8] == bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]):
        return True
    
    # AES Inverse S-Box first 8 bytes
    if data[:8] == bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38]):
        return True
    
    # SHA-256 H0 (first 4 bytes)
    if data[:4] == bytes.fromhex('6a09e667'):
        return True
    
    # SHA-1/MD5 A value
    if data[:4] == bytes.fromhex('67452301'):
        return True
    
    return False


def _is_potential_key(data: bytes) -> bool:
    """
    Check if byte array could be a cryptographic key.
    
    **CRITICAL FIX**: Added entropy threshold to reject zero buffers.
    """
    if len(data) < 8:
        return False
    
    # **FIX #3: Reject all-zeros (zero-initialized buffers)**
    if all(b == 0 for b in data):
        return False
    
    # Reject all same byte (e.g., 0xFF padding)
    if len(set(data)) == 1:
        return False
    
    # **FIX #3: Entropy Check - Reject low-entropy buffers**
    entropy = _calculate_entropy(data)
    if entropy < 3.0:  # Shannon entropy threshold
        # Entropy < 3.0 = pattern like "0000000000" or "AAAAAAAA"
        return False
    
    # Has sufficient variety (at least 4 unique bytes)
    if len(set(data)) < 4:
        return False
    
    # Likely binary data (has non-printable bytes)
    non_ascii_count = sum(1 for b in data if b < 32 or b > 126)
    if non_ascii_count < len(data) * 0.3:  # At least 30% non-ASCII
        return False
    
    # Entropy check (rough estimate)
    entropy = _calculate_entropy(data)
    if entropy < 3.0:  # Low entropy = repeating pattern
        return False
    
    return True


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence"""
    if not data:
        return 0.0
    
    import math
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1
    
    entropy = 0.0
    for count in frequency.values():
        probability = count / len(data)
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def _guess_key_type(size_bytes: int) -> str:
    """Guess algorithm from key size"""
    key_type_map = {
        8: "DES key or IV",
        16: "AES-128 key or IV",
        24: "3DES or AES-192 key",
        32: "AES-256 key or ChaCha20 key"
    }
    return key_type_map.get(size_bytes, "Unknown")
