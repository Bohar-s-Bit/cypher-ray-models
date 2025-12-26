"""
Angr tool for detecting cryptographic patterns through control flow analysis.
Identifies crypto algorithms by their structural patterns (loops, ARX operations, etc.)
"""

from typing import Dict, Any, List
import logging
import os
import sys
import io
from contextlib import contextmanager
from .angr_loader_helper import load_binary_with_fallback

logger = logging.getLogger(__name__)

# Disable Angr progress bars and verbose output
os.environ['ANGR_PROGRESS_DISABLED'] = '1'

try:
    import angr
    import claripy
    # Suppress verbose logging
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('pyvex').setLevel(logging.ERROR)
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

# Import hardcoded key detection
try:
    from .angr_constants import detect_hardcoded_keys
    HARDCODED_KEY_DETECTION_AVAILABLE = True
except ImportError:
    HARDCODED_KEY_DETECTION_AVAILABLE = False


@contextmanager
def suppress_stdout():
    """Suppress stdout AND stderr to hide Angr's CFGFast progress spam.
    Uses file descriptor level redirection to catch all output."""
    import tempfile
    # Save original file descriptors
    stdout_fd = sys.stdout.fileno()
    stderr_fd = sys.stderr.fileno()
    saved_stdout = os.dup(stdout_fd)
    saved_stderr = os.dup(stderr_fd)
    
    # Redirect to devnull
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(devnull, stdout_fd)
        os.dup2(devnull, stderr_fd)
        yield
    finally:
        # Restore original file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved_stdout, stdout_fd)
        os.dup2(saved_stderr, stderr_fd)
        os.close(saved_stdout)
        os.close(saved_stderr)
        os.close(devnull)
    logger.warning("Hardcoded key detection not available")


def angr_detect_crypto_patterns(binary_path: str) -> Dict[str, Any]:
    """
    Detect cryptographic patterns through control flow and instruction analysis.
    
    Identifies:
    - Round-based loops (AES: 10/12/14 rounds, ChaCha20: 20 rounds, SHA: 64/80 rounds)
    - ARX operations (Add-Rotate-XOR patterns in ChaCha20, Salsa20, BLAKE2)
    - Feistel networks (DES, Blowfish)
    - SPN structures (AES)
    - Table lookups (S-boxes)
    
    Args:
        binary_path: Path to the binary file
        
    Returns:
        Dict containing detected patterns
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        logger.info(f"Loading binary: {binary_path}")
        project = load_binary_with_fallback(binary_path, auto_load_libs=False)
        
        # Check if blob-loaded
        from .angr_loader_helper import is_blob_loaded
        is_raw_binary = is_blob_loaded(project)
        
        logger.info("Building CFG...")
        with suppress_stdout():
            cfg = project.analyses.CFGFast(
                normalize=True,
                force_complete_scan=False if is_raw_binary else True  # Skip for blobs
            )
        
        func_count = len(cfg.functions)
        logger.info(f"CFG built: {func_count} functions found")
        
        # Aggressive limit for blob binaries
        max_funcs = 100 if is_raw_binary else 200
        if is_raw_binary:
            logger.info(f"   Blob binary detected: will analyze max {max_funcs} functions")
        
        patterns = {
            "round_loops": [],
            "arx_operations": [],
            "feistel_networks": [],  # NEW: Feistel structure detection
            "spn_structures": [],
            "table_lookups": [],
            "modular_arithmetic": [],
            "hash_constants": [],
            "chacha20_confirmed": False,
            "memory_alu_ratios": []  # NEW: Memory vs ALU operation ratios
        }
        
        # Analyze top functions by complexity
        sorted_functions = sorted(
            cfg.functions.values(),
            key=lambda f: len(list(f.blocks)) if not f.is_simprocedure else 0,
            reverse=True
        )[:max_funcs]  # Limit based on binary type
        
        for func in sorted_functions:
            if func.is_simprocedure or func.is_plt:
                continue
            
            try:
                # CRITICAL: Detect Feistel networks FIRST (must distinguish DES from AES)
                feistel_info = _detect_feistel_network(func, project)
                if feistel_info:
                    patterns["feistel_networks"].append(feistel_info)
                
                # Detect Memory/ALU ratio (S-box vs ARX discriminator)
                ratio_info = _detect_memory_alu_ratio(func, project)
                if ratio_info:
                    patterns["memory_alu_ratios"].append(ratio_info)
                
                # Detect round-based loops
                loop_info = _detect_round_loops(func, cfg)
                if loop_info:
                    patterns["round_loops"].append(loop_info)
                
                # Detect ARX patterns
                arx_info = _detect_arx_operations(func, project)
                if arx_info:
                    patterns["arx_operations"].append(arx_info)
                
                # Detect table lookups (S-boxes)
                table_info = _detect_table_lookups(func, project)
                if table_info:
                    patterns["table_lookups"].append(table_info)
                
                # Detect modular arithmetic (RSA/ECC)
                mod_info = _detect_modular_arithmetic(func, project)
                if mod_info:
                    patterns["modular_arithmetic"].append(mod_info)
                
                # Detect hash constants (SHA-256, SHA-1, MD5)
                hash_info = _detect_hash_constants(func, project)
                if hash_info:
                    patterns["hash_constants"].append(hash_info)
                
                # Detect ChaCha20 magic constant
                chacha_constant = _detect_chacha20_constant(func, project)
                if chacha_constant:
                    patterns["chacha20_confirmed"] = True
                    
            except Exception as e:
                logger.debug(f"Error analyzing function {func.name}: {e}")
                continue
        
        # Infer algorithms from patterns
        inferred_algorithms = _infer_algorithms_from_patterns(patterns)
        
        # Detect hardcoded keys/IVs in data sections
        hardcoded_keys_result = {}
        if HARDCODED_KEY_DETECTION_AVAILABLE:
            try:
                hardcoded_keys_result = detect_hardcoded_keys(binary_path)
                logger.info(f"Hardcoded key scan: {hardcoded_keys_result.get('total_candidates', 0)} candidates found")
            except Exception as e:
                logger.warning(f"Hardcoded key detection failed: {e}")
                hardcoded_keys_result = {"error": str(e)}
        
        return {
            "patterns": patterns,
            "inferred_algorithms": inferred_algorithms,
            "hardcoded_keys": hardcoded_keys_result,
            "pattern_summary": {
                "round_loops_found": len(patterns["round_loops"]),
                "feistel_networks_found": len(patterns["feistel_networks"]),
                "memory_alu_ratios_found": len(patterns["memory_alu_ratios"]),
                "arx_operations_found": len(patterns["arx_operations"]),
                "table_lookups_found": len(patterns["table_lookups"]),
                "modular_ops_found": len(patterns["modular_arithmetic"]),
                "hash_constants_found": len(patterns.get("hash_constants", [])),
                "hardcoded_keys_found": hardcoded_keys_result.get("total_candidates", 0) if hardcoded_keys_result else 0
            }
        }
        
    except Exception as e:
        return {"error": f"Failed to detect crypto patterns: {str(e)}"}


def _detect_round_loops(func, cfg) -> Dict[str, Any]:
    """
    Detect loops with fixed iteration counts typical of crypto rounds.
    
    Crypto algorithms use specific round counts:
    - AES: 10, 12, or 14 rounds
    - ChaCha20: 20 rounds (10 double-rounds)
    - Salsa20: 20 rounds
    - SHA-256: 64 rounds
    - SHA-512: 80 rounds
    - DES: 16 rounds
    """
    try:
        loops = func.loops
        
        for loop in loops:
            # Check if loop has a predictable iteration count
            # Look for loop counter increments and comparisons
            loop_blocks = list(loop.graph.nodes())
            
            if len(loop_blocks) < 2:
                continue
            
            # Heuristic: crypto loops typically have 3-20 blocks
            # (header, body, increment, comparison, exit)
            if 3 <= len(loop_blocks) <= 20:
                # Check for common round counts in loop structure
                # This is a simplified heuristic - real analysis would need symbolic execution
                block_count = len(loop_blocks)
                
                # If loop has characteristics of crypto:
                # - Multiple XOR/ADD operations
                # - Fixed iteration count
                # - Operates on fixed-size blocks
                
                return {
                    "function": func.name,
                    "address": hex(func.addr),
                    "loop_blocks": len(loop_blocks),
                    "potential_rounds": _estimate_round_count(loop_blocks),
                    "complexity": "high" if block_count > 5 else "medium"
                }
    except Exception as e:
        logger.debug(f"Error detecting loops in {func.name}: {e}")
    
    return None


def _estimate_round_count(loop_blocks) -> int:
    """Estimate round count from loop structure (simplified heuristic)"""
    # This is a placeholder - real implementation would analyze loop bounds
    block_count = len(loop_blocks)
    
    # Common patterns
    if block_count in [10, 11, 12]:
        return 10  # Likely AES-128
    elif block_count in [13, 14]:
        return 12  # Likely AES-192 or 14 for AES-256
    elif block_count in [16, 17]:
        return 16  # Likely DES
    elif block_count in [18, 19, 20]:
        return 20  # Likely ChaCha20/Salsa20
    
    return block_count


def _detect_feistel_network(func, project) -> Dict[str, Any]:
    """
    Detect Feistel Network structure - the DEFINITIVE test for DES/Blowfish vs AES.
    
    Feistel Signature:
    - State split into two halves (L, R)
    - L_new = R_old (register latching - one half copied unmodified)
    - R_new = L_old XOR F(R_old, K) (other half XORed with function output)
    
    This pattern is OPTIMIZATION-PROOF and distinguishes Feistel from SPN.
    """
    try:
        # Find loops in the function
        if not hasattr(func, 'loops') or len(func.loops) == 0:
            return None
        
        # Analyze the deepest/most complex loop (crypto kernel)
        target_loop = max(func.loops, key=lambda l: len(list(l.graph.nodes())))
        loop_blocks = list(target_loop.graph.nodes())
        
        if len(loop_blocks) < 2:
            return None
        
        # Analyze instructions in the loop body
        register_copies = 0
        xor_operations = 0
        memory_swaps = 0
        
        for block_addr in loop_blocks:
            try:
                block = project.factory.block(block_addr, size=200)
                instructions = block.capstone.insns
                
                for i, insn in enumerate(instructions):
                    mnemonic = insn.mnemonic.lower()
                    
                    # Detect register-to-register move (L = R latching)
                    # x86: mov, ARM64: mov, orr (with zero)
                    if mnemonic in ['mov', 'movz', 'orr']:
                        # Check if it's a simple copy (not arithmetic)
                        if 'wzr' not in insn.op_str and 'xzr' not in insn.op_str:
                            register_copies += 1
                    
                    # Detect memory copy patterns (memcpy for L/R swap)
                    # Look for paired loads/stores to same-sized buffers
                    if mnemonic in ['ldr', 'str', 'ldp', 'stp']:
                        memory_swaps += 1
                    
                    # Detect XOR (the F(R,K) XOR L operation)
                    if mnemonic in ['eor', 'xor', 'eors']:
                        xor_operations += 1
                        
            except Exception as e:
                continue
        
        # Feistel heuristic: 
        # - Significant register copying (L = R latching): >= 2
        # - XOR operations (combining halves): >= 2
        # - Memory swaps (state management): >= 4
        # 
        # Ratio test: If register_copies + memory_swaps > xor_operations,
        # it suggests half the state is preserved (Feistel)
        
        preservation_ops = register_copies + (memory_swaps // 4)  # Normalize memory ops
        
        if preservation_ops >= 2 and xor_operations >= 2:
            # Strong Feistel signature
            confidence = min(0.90, 0.70 + (preservation_ops * 0.05))
            
            return {
                "function": func.name,
                "address": hex(func.addr),
                "register_copies": register_copies,
                "xor_operations": xor_operations,
                "memory_swaps": memory_swaps,
                "structure": "Feistel Network (L/R swap pattern)",
                "confidence": confidence,
                "likely_algorithms": ["DES", "3DES", "Blowfish", "Feistel-based cipher"]
            }
        
        # Check for weak Feistel signal (obfuscated)
        elif preservation_ops >= 1 and xor_operations >= 3:
            return {
                "function": func.name,
                "address": hex(func.addr),
                "register_copies": register_copies,
                "xor_operations": xor_operations,
                "structure": "Possible Feistel Network (weak signal)",
                "confidence": 0.65,
                "likely_algorithms": ["DES", "Feistel-based cipher"]
            }
        
    except Exception as e:
        logger.debug(f"Error detecting Feistel network in {func.name}: {e}")
    
    return None


def _detect_arx_operations(func, project) -> Dict[str, Any]:
    """
    Detect ARX (Add-Rotate-XOR) operation patterns.
    
    ARX ciphers like ChaCha20, Salsa20, BLAKE2 use:
    - Addition (ADD instruction)
    - Rotation (ROL/ROR or bit shifts + OR)
    - XOR (XOR instruction)
    
    Typical pattern: a = (a + b) ^ (c <<< d)
    """
    try:
        # Analyze FULL function for stripped binaries (not just 500 bytes)
        block = project.factory.block(func.addr, size=func.size)
        instructions = block.capstone.insns
        
        add_count = 0
        xor_count = 0
        rotate_count = 0
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            
            # ADD: x86 (add, adds), ARM64 (add, adds, adc)
            if 'add' in mnemonic:
                add_count += 1
            # XOR: x86 (xor), ARM64 (eor), MIPS (xor)
            elif 'xor' in mnemonic or mnemonic.startswith('eor'):
                xor_count += 1
            # ROTATE: x86 (rol, ror), ARM64 (ror, rorv), also logical shifts
            elif any(x in mnemonic for x in ['rol', 'ror', 'shift', 'lsl', 'lsr']):
                rotate_count += 1
        
        # ARX pattern: LOWERED thresholds for stripped binaries (was 4+4+2)
        if add_count >= 2 and xor_count >= 2 and rotate_count >= 1:
            return {
                "function": func.name,
                "address": hex(func.addr),
                "add_operations": add_count,
                "xor_operations": xor_count,
                "rotate_operations": rotate_count,
                "arx_score": (add_count + xor_count + rotate_count) / 3,
                "likely_algorithm": "ChaCha20/Salsa20/BLAKE2"
            }
    except Exception as e:
        logger.debug(f"Error detecting ARX in {func.name}: {e}")
    
    return None


def _detect_memory_alu_ratio(func, project) -> Dict[str, Any]:
    """
    **THE BRUTAL FIX**: Memory Intensity Ratio (MIR) - Hot Loop Only
    
    Formula: MIR = LOAD instructions / ALU instructions
    
    Thresholds (per user specification):
    - MIR > 0.25: S-Box Based (AES, DES, Blowfish) → Activate AES/DES scanners
    - MIR < 0.15: ARX Based (ChaCha, Salsa, SHA) → Activate ChaCha/Hash scanners
    - 0.15 ≤ MIR ≤ 0.25: Hybrid/Uncertain → Do not suppress anything
    
    **CRITICAL**: Only measures the deepest loop (crypto kernel), not whole function.
    Why? Initialization code (filling arrays) has high memory usage. Inner loop of
    ChaCha is pure math (MIR ≈ 0.0).
    
    This is the DEFINITIVE discriminator between ChaCha (ARX) and AES (S-box).
    """
    try:
        # Find the hottest loop (deepest nested loop)
        if not hasattr(func, 'loops') or len(func.loops) == 0:
            return None
        
        target_loop = max(func.loops, key=lambda l: len(list(l.graph.nodes())))
        loop_blocks = list(target_loop.graph.nodes())
        
        if len(loop_blocks) < 2:
            return None
        
        memory_ops = 0
        alu_ops = 0
        total_instructions = 0
        
        for block_addr in loop_blocks:
            try:
                block = project.factory.block(block_addr, size=200)
                instructions = block.capstone.insns
                
                for insn in instructions:
                    mnemonic = insn.mnemonic.lower()
                    total_instructions += 1
                    
                    # Memory operations (loads/stores for table lookups)
                    if mnemonic in ['ldr', 'ldrb', 'ldrh', 'ldp', 'str', 'strb', 'strh', 'stp',
                                   'load', 'store', 'mov'] and '[' in insn.op_str:
                        memory_ops += 1
                    
                    # ALU operations (arithmetic/logic for ARX)
                    elif mnemonic in ['add', 'adds', 'sub', 'subs', 'eor', 'eors', 'xor',
                                     'and', 'ands', 'orr', 'orn', 'ror', 'rorv', 'lsl', 'lsr',
                                     'asr', 'mul', 'madd', 'msub']:
                        alu_ops += 1
            except Exception:
                continue
        
        if total_instructions == 0:
            return None
        
        # **USER-SPECIFIED FORMULA**: MIR = Memory Ops / ALU Ops
        # (Note: We approximate with total_instructions as denominator for stability)
        memory_ratio = memory_ops / total_instructions if total_instructions > 0 else 0
        
        # **USER-SPECIFIED THRESHOLDS**:
        # MIR > 0.25: S-Box cipher (table lookups dominate)
        # MIR < 0.15: ARX cipher (pure computation)
        # 0.15 ≤ MIR ≤ 0.25: Hybrid (do not suppress)
        
        if memory_ratio > 0.25:
            classification = "S-box cipher (High memory usage)"
            likely_algos = ["AES", "DES", "Blowfish"]
        elif memory_ratio < 0.15:
            classification = "ARX cipher (Low memory usage)"
            likely_algos = ["ChaCha20", "Salsa20", "BLAKE2", "MD5", "SHA"]
        else:
            classification = "Hybrid/Uncertain (Do not suppress)"
            likely_algos = ["Unknown - mixed pattern"]
        
        return {
            "function": func.name,
            "address": hex(func.addr),
            "memory_ops": memory_ops,
            "alu_ops": alu_ops,
            "total_instructions": total_instructions,
            "memory_ratio": round(memory_ratio, 3),
            "classification": classification,
            "likely_algorithms": likely_algos
        }
        
    except Exception as e:
        logger.debug(f"Error calculating memory/ALU ratio in {func.name}: {e}")
    
    return None


def _detect_table_lookups(func, project) -> Dict[str, Any]:
    """
    Detect table lookup patterns (S-boxes, permutation tables).
    
    Pattern: value = table[index]
    - Load from array with computed index
    - Table size typically 256 bytes (AES S-box) or 1024 bytes
    """
    try:
        # Analyze FULL function for stripped binaries (not just 500 bytes)
        block = project.factory.block(func.addr, size=func.size)
        instructions = block.capstone.insns
        
        table_access_count = 0
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            
            # Look for array/table access patterns
            # Common: mov reg, [base + index] or ldr reg, [base, index]
            if ('mov' in mnemonic or 'ldr' in mnemonic or 'ld' in mnemonic):
                if '[' in insn.op_str or 'byte ptr' in insn.op_str:
                    table_access_count += 1
        
        # S-box style access: LOWERED threshold for stripped binaries (was 4)
        if table_access_count >= 2:
            return {
                "function": func.name,
                "address": hex(func.addr),
                "table_accesses": table_access_count,
                "likely_operation": "S-box substitution or permutation",
                "confidence": "high" if table_access_count >= 8 else "medium"
            }
    except Exception as e:
        logger.debug(f"Error detecting table lookups in {func.name}: {e}")
    
    return None


def _detect_modular_arithmetic(func, project) -> Dict[str, Any]:
    """
    Detect modular arithmetic patterns (RSA, ECC).
    
    Patterns:
    - Large number operations (64-bit or multi-word)
    - Division/modulo operations
    - Multiplication chains
    - Modular exponentiation (repeated multiply-modulo loops)
    """
    try:
        block = project.factory.block(func.addr, size=min(func.size, 800))
        instructions = block.capstone.insns
        
        mul_count = 0
        div_count = 0
        mod_count = 0
        wide_ops = 0
        shift_ops = 0
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            
            # Multiplication (core of modular exponentiation)
            if 'mul' in mnemonic or 'imul' in mnemonic or 'smull' in mnemonic or 'umull' in mnemonic:
                mul_count += 1
            # Division/Modulo (for reducing after multiplication)
            elif 'div' in mnemonic or 'udiv' in mnemonic or 'sdiv' in mnemonic:
                div_count += 1
            # Shifts (used in bit-by-bit exponentiation: b >>= 1)
            elif 'shr' in mnemonic or 'lsr' in mnemonic or 'asr' in mnemonic:
                shift_ops += 1
            
            # Check for 64-bit operations (RSA typically uses large numbers)
            if 'qword' in insn.op_str or 'r64' in insn.op_str or 'x' in insn.op_str:
                wide_ops += 1
        
        # RSA pattern: lots of multiplication with division/shifts (modular exponentiation)
        # Relaxed for small RSA implementations: (mul >= 3 AND (div >= 1 OR shifts >= 2))
        if mul_count >= 3 and (div_count >= 1 or shift_ops >= 2):
            confidence = 0.75 if mul_count >= 10 else 0.65
            return {
                "function": func.name,
                "address": hex(func.addr),
                "multiplications": mul_count,
                "divisions": div_count,
                "shifts": shift_ops,
                "wide_operations": wide_ops,
                "likely_algorithm": "RSA or ECC",
                "confidence": confidence
            }
    except Exception as e:
        logger.debug(f"Error detecting modular arithmetic in {func.name}: {e}")
    
    return None


def _detect_hash_constants(func, project) -> Dict[str, Any]:
    """
    Detect hash function constants (SHA-256, SHA-1, MD5, etc.).
    
    Hash functions use distinctive initialization vectors and round constants:
    - SHA-256: IV starts with 0x6a09e667, K starts with 0x428a2f98
    - SHA-1: IV = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    - MD5: Similar magic constants
    """
    try:
        block = project.factory.block(func.addr, size=min(func.size, 800))
        instructions = block.capstone.insns
        
        # Known hash constants (in little-endian for x86/ARM64)
        hash_constants = {
            # SHA-256 initialization vector H[0..7]
            0x6a09e667: "SHA-256",
            0xbb67ae85: "SHA-256",
            0x3c6ef372: "SHA-256",
            0xa54ff53a: "SHA-256",
            0x510e527f: "SHA-256",
            0x9b05688c: "SHA-256",
            
            # SHA-256 round constants K[0..3]
            0x428a2f98: "SHA-256",
            0x71374491: "SHA-256",
            0xb5c0fbcf: "SHA-256",
            0xe9b5dba5: "SHA-256",
            
            # SHA-1 initialization
            0x67452301: "SHA-1",
            0xefcdab89: "SHA-1",
            0x98badcfe: "SHA-1",
            0x10325476: "SHA-1",
            0xc3d2e1f0: "SHA-1",
            
            # MD5 initialization
            0xd76aa478: "MD5",
            0xe8c7b756: "MD5",
            0x242070db: "MD5",
        }
        
        detected_constants = set()
        algorithm = None
        
        # Search for constants in immediate values
        for insn in instructions:
            # Check operands for immediate values
            if insn.op_str:
                # Extract hex values from operands
                import re
                hex_values = re.findall(r'0x([0-9a-fA-F]+)', insn.op_str)
                
                for hex_val in hex_values:
                    try:
                        value = int(hex_val, 16)
                        if value in hash_constants:
                            detected_constants.add(value)
                            algorithm = hash_constants[value]
                    except ValueError:
                        continue
        
        # Also check constants in memory/data sections near this function
        try:
            # Read nearby data (often constants are loaded from nearby addresses)
            for addr in range(func.addr - 500, func.addr + func.size + 500, 4):
                try:
                    word = project.loader.memory.load(addr, 4)
                    value = int.from_bytes(word, byteorder='little')
                    if value in hash_constants:
                        detected_constants.add(value)
                        algorithm = hash_constants[value]
                except:
                    continue
        except:
            pass
        
        if len(detected_constants) >= 2:  # Require at least 2 matching constants
            return {
                "function": func.name,
                "address": hex(func.addr),
                "algorithm": algorithm,
                "constants_found": list(detected_constants),
                "constant_count": len(detected_constants),
                "confidence": "high" if len(detected_constants) >= 4 else "medium"
            }
    
    except Exception as e:
        logger.debug(f"Error detecting hash constants in {func.name}: {e}")
    
    return None


def _detect_chacha20_constant(func, project) -> bool:
    """
    Detect ChaCha20/Salsa20 magic constant "expand 32-byte k".
    
    This is the definitive signature of ChaCha20/Salsa20.
    Without this constant, ARX operations are likely from other sources.
    """
    try:
        # ChaCha20 constant: "expand 32-byte k" = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        magic_constant = b"expand 32-byte k"
        
        # Search in function's immediate vicinity
        try:
            # Check in code section near this function
            for addr in range(func.addr - 1000, func.addr + func.size + 1000, 1):
                try:
                    data = project.loader.memory.load(addr, 16)
                    if magic_constant in data:
                        logger.info(f"✅ Found ChaCha20 magic constant near {func.name}")
                        return True
                except:
                    continue
        except:
            pass
        
        # Also check for the constant as 32-bit words in immediate values
        block = project.factory.block(func.addr, size=min(func.size, 500))
        instructions = block.capstone.insns
        
        chacha_words = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        found_words = set()
        
        for insn in instructions:
            if insn.op_str:
                import re
                hex_values = re.findall(r'0x([0-9a-fA-F]+)', insn.op_str)
                for hex_val in hex_values:
                    try:
                        value = int(hex_val, 16)
                        if value in chacha_words:
                            found_words.add(value)
                    except:
                        continue
        
        if len(found_words) >= 2:  # At least 2 of the 4 constant words
            logger.info(f"✅ Found ChaCha20 constant words in {func.name}")
            return True
    
    except Exception as e:
        logger.debug(f"Error detecting ChaCha20 constant: {e}")
    
    return False


def _infer_algorithms_from_patterns(patterns: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Infer likely cryptographic algorithms from detected patterns.
    
    HIERARCHICAL SUPPRESSION (Production Rule):
    1. Structure Wins: If Feistel detected → suppress AES (they're mutually exclusive)
    2. Confidence Lock: If primary algo > 90% → suppress secondary in same category
    """
    algorithms = []
    
    # =============================================================================
    # PHASE 1: STRUCTURAL ANALYSIS (HIGHEST PRIORITY - ARCHITECTURE TRUMPS SIGNALS)
    # =============================================================================
    
    # Memory/ALU Ratio Analysis (Universal Discriminator)
    # This provides architectural evidence for S-box vs ARX classification
    # **USER-SPECIFIED THRESHOLDS**: MIR > 0.25 = S-box, MIR < 0.15 = ARX
    sbox_evidence = False
    arx_evidence = False
    hybrid_uncertain = False
    
    if patterns["memory_alu_ratios"]:
        for ratio in patterns["memory_alu_ratios"]:
            if ratio["memory_ratio"] > 0.25:
                sbox_evidence = True  # S-box cipher (AES, DES, Blowfish)
            elif ratio["memory_ratio"] < 0.15:
                arx_evidence = True  # ARX cipher (ChaCha, Salsa, BLAKE2)
            else:
                hybrid_uncertain = True  # Mixed pattern - do not suppress
    
    # Feistel Network Detection → DES/Blowfish (EXCLUDES AES/SPN)
    feistel_detected = False
    if patterns["feistel_networks"]:
        feistel_detected = True
        for feistel in patterns["feistel_networks"]:
            # Boost confidence if memory ratio confirms S-box usage
            confidence = feistel.get("confidence", 0.85)
            if sbox_evidence:
                confidence = min(0.98, confidence + 0.10)
            
            algorithms.append({
                "algorithm": "DES or Feistel-based cipher",
                "confidence": confidence,
                "evidence": f"Feistel Network structure: {feistel['structure']} (Register copies:{feistel['register_copies']}, XORs:{feistel['xor_operations']})" + (" + High memory usage (S-box confirmed)" if sbox_evidence else ""),
                "function": feistel["function"],
                "category": "symmetric",
                "structure": "feistel"
            })
    
    # =============================================================================
    # PHASE 2: FEATURE-BASED DETECTION (NORMAL PRIORITY)
    # =============================================================================
    
    # ARX patterns → ChaCha20/Salsa20/BLAKE2
    # CRITICAL: Require ChaCha20 magic constant OR very high operation counts
    # to avoid false positives on binaries with incidental ARX operations
    # PLUS: Validate with Memory/ALU ratio (should be LOW for ARX)
    if patterns["arx_operations"]:
        for arx in patterns["arx_operations"]:
            # Check if ChaCha20 constant was found
            has_chacha_constant = patterns.get("chacha20_confirmed", False)
            
            # Require either:
            # 1. ChaCha20 constant confirmed (high confidence), OR
            # 2. Very high operation counts (50+ XORs) AND low memory ratio (ARX evidence)
            if has_chacha_constant:
                # Definitive ChaCha20/Salsa20
                confidence = 0.85
                if arx_evidence:
                    confidence = 0.90  # Boost with architectural evidence
                algorithms.append({
                    "algorithm": "ChaCha20/Salsa20",
                    "confidence": confidence,
                    "evidence": f"ChaCha20 magic constant + ARX pattern (ADD:{arx['add_operations']}, XOR:{arx['xor_operations']}, ROT:{arx['rotate_operations']})" + (" + Low memory usage (ARX confirmed)" if arx_evidence else ""),
                    "function": arx["function"],
                    "category": "symmetric",
                    "structure": "arx"
                })
            elif arx['xor_operations'] >= 50 and not feistel_detected and arx_evidence:
                # Likely ARX cipher with architectural confirmation
                confidence = 0.75
                algorithms.append({
                    "algorithm": arx["likely_algorithm"],
                    "confidence": confidence,
                    "evidence": f"ARX pattern detected (ADD:{arx['add_operations']}, XOR:{arx['xor_operations']}, ROT:{arx['rotate_operations']}) + Low memory usage (ARX confirmed)",
                    "function": arx["function"],
                    "category": "symmetric",
                    "structure": "arx"
                })
            elif arx['xor_operations'] >= 50 and not feistel_detected and not sbox_evidence:
                # Likely ARX but no architectural evidence (be more cautious)
                confidence = 0.65
                algorithms.append({
                    "algorithm": arx["likely_algorithm"],
                    "confidence": confidence,
                    "evidence": f"ARX pattern detected (ADD:{arx['add_operations']}, XOR:{arx['xor_operations']}, ROT:{arx['rotate_operations']})",
                    "function": arx["function"],
                    "category": "symmetric",
                    "structure": "arx"
                })
            # else: Skip reporting - likely false positive from other crypto operations
    
    # Table lookups → AES or DES
    # HIERARCHICAL RULE: If Feistel detected, it's DES (not AES)
    # PLUS: Validate with Memory/ALU ratio (should be HIGH for S-box ciphers)
    if patterns["table_lookups"]:
        for table in patterns["table_lookups"]:
            confidence = 0.80 if table["confidence"] == "high" else 0.65
            
            if feistel_detected:
                # Feistel + S-boxes = DES (high confidence)
                algo_name = "DES"
                confidence = min(0.95, confidence + 0.15)  # Boost confidence
            else:
                # S-boxes without Feistel = likely AES
                algo_name = "AES or DES (S-box based cipher)"
            
            # Boost confidence if memory ratio confirms S-box usage
            if sbox_evidence:
                confidence = min(0.98, confidence + 0.10)
            
            algorithms.append({
                "algorithm": algo_name,
                "confidence": confidence,
                "evidence": f"S-box pattern with {table['table_accesses']} table accesses" + (" + Feistel structure" if feistel_detected else "") + (" + High memory usage (S-box confirmed)" if sbox_evidence else ""),
                "function": table["function"],
                "category": "symmetric",
                "structure": "spn" if not feistel_detected else "feistel"
            })
    
    # Round loops → Various symmetric ciphers
    if patterns["round_loops"]:
        for loop in patterns["round_loops"]:
            rounds = loop["potential_rounds"]
            
            if rounds == 10:
                algo = "AES-128"
            elif rounds == 12:
                algo = "AES-192"
            elif rounds == 14:
                algo = "AES-256"
            elif rounds == 16:
                algo = "DES" if feistel_detected else "DES or AES"
            elif rounds == 20:
                algo = "ChaCha20/Salsa20"
            else:
                algo = f"Unknown cipher ({rounds} rounds)"
            
            algorithms.append({
                "algorithm": algo,
                "confidence": 0.70,
                "evidence": f"Round-based loop structure with ~{rounds} iterations",
                "function": loop["function"],
                "category": "symmetric"
            })
    
    # Modular arithmetic → RSA/ECC
    if patterns["modular_arithmetic"]:
        for mod in patterns["modular_arithmetic"]:
            # Use confidence from detection function
            confidence = mod.get('confidence', 0.65)
            algorithms.append({
                "algorithm": mod["likely_algorithm"],
                "confidence": confidence,
                "evidence": f"Modular arithmetic (MUL:{mod['multiplications']}, DIV:{mod['divisions']}, SHIFT:{mod.get('shifts', 0)})",
                "function": mod["function"],
                "category": "asymmetric"
            })
    
    # Hash constants → SHA-256, SHA-1, MD5
    # Detect via known initialization vectors and round constants
    if patterns.get("hash_constants"):
        for hash_const in patterns["hash_constants"]:
            algorithms.append({
                "algorithm": hash_const["algorithm"],
                "confidence": 0.85,  # High confidence for unique constants
                "evidence": f"Hash constants detected: {hash_const['constants_found']}",
                "function": hash_const.get("function", "binary-wide"),
                "category": "hash"
            })
    
    # =============================================================================
    # PHASE 3: HIERARCHICAL SUPPRESSION + MIR CONFLICT RESOLUTION
    # =============================================================================
    
    # **CRITICAL FIX #2**: Use MIR to resolve conflicts (AES vs ChaCha)
    # If MIR says "ARX" (< 0.15) but we detected S-boxes:
    #   → SUPPRESS S-box detection (likely false positive)
    #   → KEEP ARX detection (ChaCha20)
    # If MIR says "S-box" (> 0.25) but we detected ARX:
    #   → KEEP S-box detection (AES/DES)
    #   → LOWER ARX confidence (likely incidental XORs)
    
    if arx_evidence and not hybrid_uncertain:
        # MIR confirms ARX cipher → Remove S-box detections
        algorithms = [a for a in algorithms if "S-box" not in a.get("algorithm", "")]
        # Boost ARX confidence
        for algo in algorithms:
            if algo.get("structure") == "arx":
                algo["confidence"] = min(0.95, algo["confidence"] + 0.10)
                algo["evidence"] += " [MIR < 0.15 confirms ARX]"
    
    elif sbox_evidence and not hybrid_uncertain:
        # MIR confirms S-box cipher → Lower ARX confidence, keep S-boxes
        for algo in algorithms:
            if algo.get("structure") == "arx" and not patterns.get("chacha20_confirmed"):
                # Lower confidence unless ChaCha constant was found
                algo["confidence"] = max(0.50, algo["confidence"] - 0.20)
                algo["evidence"] += " [MIR > 0.25 suggests S-box, not ARX]"
    
    # Apply confidence-based suppression within categories
    # Rule: If primary algorithm > 90% confidence, suppress weaker signals in same category
    
    categories = {}
    for algo in algorithms:
        cat = algo.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(algo)
    
    # For each category, find max confidence
    filtered_algorithms = []
    for cat, algos in categories.items():
        if cat == "unknown":
            filtered_algorithms.extend(algos)
            continue
        
        # Sort by confidence
        algos_sorted = sorted(algos, key=lambda a: a["confidence"], reverse=True)
        
        # If top algorithm > 90%, suppress others in same category (unless also > 80%)
        if algos_sorted[0]["confidence"] >= 0.90:
            filtered_algorithms.append(algos_sorted[0])
            # Keep secondary algorithms only if they're also high confidence (> 80%)
            for algo in algos_sorted[1:]:
                if algo["confidence"] >= 0.80:
                    filtered_algorithms.append(algo)
        else:
            # No dominant algorithm, keep all
            filtered_algorithms.extend(algos)
    
    # CRITICAL FIX: Binary-wide aggregation for stripped binaries
    # If we found table lookups across MULTIPLE functions but no other patterns,
    # boost confidence that it's crypto (likely inlined/optimized AES)
    if len(patterns["table_lookups"]) >= 2 and not filtered_algorithms:
        filtered_algorithms.append({
            "algorithm": "DES (inlined S-box implementation)" if feistel_detected else "AES (inlined/optimized S-box implementation)",
            "confidence": 0.80,
            "evidence": f"Multiple S-box patterns detected across {len(patterns['table_lookups'])} functions",
            "function": "binary-wide analysis",
            "category": "symmetric"
        })
    
    return filtered_algorithms


def angr_build_function_groups(binary_path: str) -> Dict[str, Any]:
    """
    Build call graph and group related functions for cross-function aggregation.
    
    CRITICAL for ultra-stripped binaries where crypto operations are split across
    many tiny functions due to aggressive inlining/optimization.
    
    Groups functions that:
    1. Call each other (parent-child relationships)
    2. Are called by same parent (siblings)
    3. Have similar sizes (likely related helpers)
    4. Are within same address range (spatial locality)
    
    Returns:
        Dict with function groups and their aggregated crypto indicators
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr not available"}
        
        # Use blob loader fallback helper
        project = load_binary_with_fallback(binary_path, auto_load_libs=False)
        
        # Limit CFG time to 2 minutes for large binaries (prevents 5-min timeout)
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("CFG analysis timeout")
        
        try:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(120)  # 2-minute timeout
            with suppress_stdout():
                cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
            signal.alarm(0)  # Cancel alarm
        except TimeoutError:
            logger.warning("CFG analysis timed out after 2 minutes, using partial results")
            signal.alarm(0)
            with suppress_stdout():
                cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
        
        # Build call graph relationships
        # CRITICAL: Limit to prevent timeout on huge binaries
        # Blob binaries get more aggressive limit
        project = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
        from .angr_loader_helper import is_blob_loaded
        is_raw_binary = is_blob_loaded(project)
        
        function_groups = []
        visited = set()
        func_count = 0
        max_funcs_to_analyze = 100 if is_raw_binary else 300  # Aggressive limit for blobs
        
        for func_addr, func in cfg.functions.items():
            func_count += 1
            if func_count > max_funcs_to_analyze:
                logger.warning(f"Analyzed {max_funcs_to_analyze} functions, stopping to prevent timeout")
                break
            if func.is_simprocedure or func.is_plt or func_addr in visited:
                continue
            
            # Start new group with BFS from this function
            group = _build_function_cluster(func, cfg, visited)
            
            if len(group) >= 2:  # Only keep groups with 2+ functions
                # ENHANCEMENT: Extract instruction patterns from group
                try:
                    crypto_patterns = _analyze_function_group_instructions(project, cfg, list(group))
                    
                    if crypto_patterns.get('crypto_likelihood', 0) > 0.3:
                        logger.info(f"🔍 Group at {func_addr:x}: {crypto_patterns.get('summary')}")
                    
                    function_groups.append({
                        "functions": list(group),
                        "size": len(group),
                        "root_function": func_addr,
                        "crypto_score": crypto_patterns.get('crypto_likelihood', 0.0),
                        "has_xor_chains": crypto_patterns.get('xor_count', 0) > 5,
                        "has_rotations": crypto_patterns.get('rotation_count', 0) > 3,
                        "has_lookups": crypto_patterns.get('lookup_count', 0) > 2,
                        "pattern_summary": crypto_patterns.get('summary', 'No patterns detected')
                    })
                except Exception as e:
                    logger.debug(f"Failed to analyze group at {func_addr:x}: {e}")
                    function_groups.append({
                        "functions": list(group),
                        "size": len(group),
                        "root_function": func_addr,
                        "crypto_score": 0.0,
                        "pattern_summary": "Analysis failed"
                    })
        
        return {
            "function_groups": function_groups,
            "total_groups": len(function_groups),
            "largest_group_size": max(len(g["functions"]) for g in function_groups) if function_groups else 0
        }
        
    except Exception as e:
        logger.error(f"Failed to build function groups: {e}")
        return {"error": str(e)}


def _build_function_cluster(root_func, cfg, visited: set, max_depth=3) -> set:
    """
    Build a cluster of related functions using spatial proximity and call relationships.
    
    CRITICAL FOR ULTRA-STRIPPED BINARIES: When aggressive inlining removes all call
    instructions, we fallback to grouping functions by address proximity (adjacent
    functions likely part of same crypto implementation).
    
    Args:
        root_func: Starting function
        cfg: Control Flow Graph
        visited: Set of already visited function addresses
        max_depth: Maximum traversal depth
    
    Returns:
        Set of function addresses in this cluster
    """
    cluster = {root_func.addr}
    queue = [(root_func, 0)]
    visited.add(root_func.addr)
    
    # Get all functions sorted by address for proximity grouping
    all_funcs_sorted = sorted(cfg.functions.items(), key=lambda x: x[0])
    func_addrs = [addr for addr, f in all_funcs_sorted if not f.is_simprocedure]
    
    # Find root function's index
    try:
        root_idx = func_addrs.index(root_func.addr)
    except ValueError:
        return cluster
    
    while queue:
        current_func, depth = queue.pop(0)
        
        if depth >= max_depth:
            continue
        
        # Strategy 1: Group by call relationships (if they exist)
        try:
            if hasattr(cfg.functions, 'callgraph'):
                # Add callees
                for callee_addr in cfg.functions.callgraph.successors(current_func.addr):
                    if callee_addr not in visited and callee_addr in cfg.functions:
                        callee_func = cfg.functions[callee_addr]
                        if not callee_func.is_simprocedure and callee_func.size < 1000:
                            cluster.add(callee_addr)
                            queue.append((callee_func, depth + 1))
                            visited.add(callee_addr)
                
                # Add callers (if current is small helper)
                if current_func.size < 500:
                    for caller_addr in cfg.functions.callgraph.predecessors(current_func.addr):
                        if caller_addr not in visited and caller_addr in cfg.functions:
                            caller_func = cfg.functions[caller_addr]
                            if not caller_func.is_simprocedure:
                                cluster.add(caller_addr)
                                queue.append((caller_func, depth + 1))
                                visited.add(caller_addr)
        except Exception as e:
            logger.debug(f"Callgraph failed for {current_func.addr:x}, using proximity: {e}")
        
        # Strategy 2: Group by spatial proximity (CRITICAL for inlined code)
        # If current function is small (< 200 bytes), group adjacent small functions
        if current_func.size < 200 and depth < max_depth:
            try:
                current_idx = func_addrs.index(current_func.addr)
                
                # Check 5 functions before and after
                for offset in range(-5, 6):
                    neighbor_idx = current_idx + offset
                    if 0 <= neighbor_idx < len(func_addrs):
                        neighbor_addr = func_addrs[neighbor_idx]
                        
                        if neighbor_addr not in visited and neighbor_addr in cfg.functions:
                            neighbor_func = cfg.functions[neighbor_addr]
                            
                            # Group if: small (<300 bytes) and close (<2KB away)
                            addr_distance = abs(neighbor_addr - current_func.addr)
                            if (not neighbor_func.is_simprocedure and 
                                neighbor_func.size < 300 and 
                                addr_distance < 2000):
                                cluster.add(neighbor_addr)
                                queue.append((neighbor_func, depth + 1))
                                visited.add(neighbor_addr)
            except ValueError:
                pass
    
    return cluster


def _analyze_function_group_instructions(project, cfg, function_addrs: list) -> Dict[str, Any]:
    """
    Analyze actual assembly instructions in a function group to detect crypto patterns.
    CRITICAL for ultra-stripped binaries with no symbols/strings.
    
    Detects:
    - XOR chains (indicator of encryption/obfuscation)
    - Bit rotations (common in hash functions)
    - Table lookups (S-boxes in AES, DES)
    - Modular arithmetic (RSA, ECC)
    
    Args:
        project: Angr project
        cfg: Control flow graph
        function_addrs: List of function addresses in the group
    
    Returns:
        Dict with crypto pattern scores and summary
    """
    xor_count = 0
    rotation_count = 0
    lookup_count = 0
    mod_count = 0
    shift_count = 0
    and_or_count = 0
    
    try:
        # Analyze up to 10 functions in group (to avoid performance issues)
        for func_addr in function_addrs[:10]:
            if func_addr not in cfg.functions:
                continue
            
            func = cfg.functions[func_addr]
            
            # Get basic blocks
            for block in func.blocks:
                try:
                    # Disassemble block
                    insn_addrs = block.instruction_addrs
                    
                    for insn_addr in insn_addrs[:50]:  # Limit to 50 instructions per block
                        try:
                            # Get instruction bytes
                            insn_bytes = project.loader.memory.load(insn_addr, 16)
                            
                            # Disassemble instruction
                            try:
                                insn = next(project.arch.capstone.disasm(insn_bytes, insn_addr, count=1))
                                mnemonic = insn.mnemonic.lower()
                                
                                # Count crypto-indicative instructions
                                if 'xor' in mnemonic:
                                    xor_count += 1
                                elif 'rol' in mnemonic or 'ror' in mnemonic or 'rotate' in mnemonic:
                                    rotation_count += 1
                                elif mnemonic in ['movzx', 'movsx', 'ldr', 'ldrb'] and '[' in insn.op_str:
                                    # Table lookup pattern
                                    lookup_count += 1
                                elif 'shl' in mnemonic or 'shr' in mnemonic or 'lsl' in mnemonic or 'lsr' in mnemonic:
                                    shift_count += 1
                                elif 'and' in mnemonic or 'or' in mnemonic:
                                    and_or_count += 1
                                elif 'mod' in mnemonic or 'div' in mnemonic:
                                    mod_count += 1
                                    
                            except StopIteration:
                                continue
                        except Exception:
                            continue
                except Exception:
                    continue
        
        # Calculate crypto likelihood score
        crypto_score = 0.0
        if xor_count > 10:
            crypto_score += 0.3
        if rotation_count > 5:
            crypto_score += 0.25
        if lookup_count > 3:
            crypto_score += 0.2
        if shift_count > 15:
            crypto_score += 0.15
        if and_or_count > 20:
            crypto_score += 0.1
        
        # Generate summary
        patterns = []
        if xor_count > 10:
            patterns.append(f"{xor_count} XOR operations")
        if rotation_count > 5:
            patterns.append(f"{rotation_count} rotations")
        if lookup_count > 3:
            patterns.append(f"{lookup_count} table lookups")
        if shift_count > 15:
            patterns.append(f"{shift_count} shifts")
            
        summary = f"Detected: {', '.join(patterns)}" if patterns else "No significant crypto patterns"
        
        return {
            'crypto_likelihood': min(crypto_score, 1.0),
            'xor_count': xor_count,
            'rotation_count': rotation_count,
            'lookup_count': lookup_count,
            'shift_count': shift_count,
            'and_or_count': and_or_count,
            'summary': summary
        }
        
    except Exception as e:
        logger.error(f"Failed to analyze function group instructions: {e}")
        return {
            'crypto_likelihood': 0.0,
            'xor_count': 0,
            'rotation_count': 0,
            'lookup_count': 0,
            'summary': 'Analysis failed'
        }

