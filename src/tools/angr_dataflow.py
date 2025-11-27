"""
Angr tool for data flow analysis to track cryptographic operations.
Tracks how data is transformed through XOR chains, rotations, substitutions, etc.
"""

from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def angr_analyze_dataflow(binary_path: str) -> Dict[str, Any]:
    """
    Analyze data flow patterns typical of cryptographic operations.
    
    Tracks:
    - XOR chains (data XORed multiple times - key mixing)
    - Bit rotations (ROL/ROR - diffusion)
    - Substitutions (table lookups - confusion)
    - Mixing operations (multiple ops on same data)
    
    Args:
        binary_path: Path to the binary file
        
    Returns:
        Dict containing data flow analysis results
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        logger.info(f"Loading binary for dataflow: {binary_path}")
        project = angr.Project(binary_path, auto_load_libs=False)
        
        logger.info("Building CFG for dataflow...")
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=True
        )
        logger.info(f"CFG built: {len(cfg.functions)} functions found")
        
        dataflow_patterns = {
            "xor_chains": [],
            "bit_rotations": [],
            "data_mixing": [],
            "byte_substitutions": []
        }
        
        # Analyze functions for data transformation patterns
        sorted_functions = sorted(
            cfg.functions.values(),
            key=lambda f: len(list(f.blocks)) if not f.is_simprocedure else 0,
            reverse=True
        )[:30]  # Top 30 complex functions
        
        for func in sorted_functions:
            if func.is_simprocedure or func.is_plt:
                continue
            
            try:
                # Analyze XOR operations (key mixing, stream cipher output)
                xor_info = _analyze_xor_operations(func, project)
                if xor_info:
                    dataflow_patterns["xor_chains"].append(xor_info)
                
                # Analyze bit rotations (diffusion in ARX ciphers)
                rotation_info = _analyze_bit_rotations(func, project)
                if rotation_info:
                    dataflow_patterns["bit_rotations"].append(rotation_info)
                
                # Analyze data mixing (multiple operations on same data)
                mixing_info = _analyze_data_mixing(func, project)
                if mixing_info:
                    dataflow_patterns["data_mixing"].append(mixing_info)
                
            except Exception as e:
                logger.debug(f"Error analyzing dataflow in {func.name}: {e}")
                continue
        
        # Calculate crypto likelihood scores
        crypto_score = _calculate_crypto_likelihood(dataflow_patterns)
        
        return {
            "dataflow_patterns": dataflow_patterns,
            "crypto_likelihood_score": crypto_score,
            "summary": {
                "xor_chains_found": len(dataflow_patterns["xor_chains"]),
                "rotations_found": len(dataflow_patterns["bit_rotations"]),
                "mixing_operations_found": len(dataflow_patterns["data_mixing"])
            },
            "assessment": _assess_crypto_characteristics(crypto_score)
        }
        
    except Exception as e:
        return {"error": f"Failed to analyze dataflow: {str(e)}"}


def _analyze_xor_operations(func, project) -> Dict[str, Any]:
    """
    Detect XOR chains - multiple XOR operations suggesting key mixing or stream cipher.
    
    Patterns:
    - data ^= key1; data ^= key2; (multiple XORs)
    - output = plaintext ^ keystream; (stream cipher)
    - round_key = key ^ constant; (key derivation)
    """
    try:
        # Analyze FULL function for stripped binaries (not just 500 bytes)
        block = project.factory.block(func.addr, size=func.size)
        instructions = block.capstone.insns
        
        xor_count = 0
        xor_details = []
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            # XOR: x86 (xor), ARM64 (eor), MIPS (xor)
            if 'xor' in mnemonic or mnemonic.startswith('eor'):
                xor_count += 1
                xor_details.append({
                    "address": hex(insn.address),
                    "instruction": f"{insn.mnemonic} {insn.op_str}"
                })
        
        # LOWERED threshold for stripped binaries (was 3)
        if xor_count >= 2:
            return {
                "function": func.name,
                "address": hex(func.addr),
                "xor_count": xor_count,
                "operations": xor_details[:10],  # First 10 for brevity
                "pattern_type": _classify_xor_pattern(xor_count),
                "crypto_indicator": "strong" if xor_count >= 5 else "moderate"
            }
    except Exception as e:
        logger.debug(f"Error analyzing XOR in {func.name}: {e}")
    
    return None


def _classify_xor_pattern(xor_count: int) -> str:
    """Classify XOR pattern based on count"""
    if xor_count >= 8:
        return "key_schedule or stream_cipher"
    elif xor_count >= 5:
        return "key_mixing or round_function"
    elif xor_count >= 3:
        return "basic_crypto_operation"
    return "unknown"


def _analyze_bit_rotations(func, project) -> Dict[str, Any]:
    """
    Detect bit rotation patterns (ROL/ROR) typical of ARX ciphers and hash functions.
    
    Rotations provide diffusion in:
    - ChaCha20: Quarter-round with specific rotation amounts (16, 12, 8, 7)
    - SHA-256: Sigma functions with rotations (7, 18, 3)
    - MD5: Variable rotations per round
    """
    try:
        # Analyze FULL function for stripped binaries (not just 500 bytes)
        block = project.factory.block(func.addr, size=func.size)
        instructions = block.capstone.insns
        
        rotation_count = 0
        rotation_amounts = []
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            
            # Direct rotations: x86 (rol, ror), ARM64 (ror, rorv)
            if 'rol' in mnemonic or 'ror' in mnemonic:
                rotation_count += 1
                
                # Try to extract rotation amount
                if ',' in insn.op_str:
                    parts = insn.op_str.split(',')
                    if len(parts) > 1:
                        try:
                            amount = int(parts[1].strip(), 0)
                            rotation_amounts.append(amount)
                        except:
                            pass
            
            # Emulated rotations (shift + or): x86 (shl, shr), ARM64 (lsl, lsr, asr)
            elif any(x in mnemonic for x in ['shl', 'shr', 'shift', 'lsl', 'lsr', 'asr']):
                # Shifts often combined with OR to create rotation
                rotation_count += 0.5  # Count as half-rotation
        
        # LOWERED threshold for stripped binaries (was 2)
        if rotation_count >= 1:
            return {
                "function": func.name,
                "address": hex(func.addr),
                "rotation_count": int(rotation_count),
                "rotation_amounts": rotation_amounts[:10],
                "likely_algorithm": _infer_from_rotations(rotation_amounts),
                "crypto_indicator": "strong" if rotation_count >= 4 else "moderate"
            }
    except Exception as e:
        logger.debug(f"Error analyzing rotations in {func.name}: {e}")
    
    return None


def _infer_from_rotations(rotation_amounts: List[int]) -> str:
    """Infer algorithm from rotation amounts"""
    if not rotation_amounts:
        return "unknown_arx_cipher"
    
    # ChaCha20 signature: 16, 12, 8, 7
    if any(amt in [16, 12, 8, 7] for amt in rotation_amounts):
        return "ChaCha20 (signature rotations: 16, 12, 8, 7)"
    
    # SHA-256 signature: 2, 13, 22, 6, 11, 25
    if any(amt in [2, 13, 22, 6, 11, 25] for amt in rotation_amounts):
        return "SHA-256 (signature rotations)"
    
    # MD5: 7, 12, 17, 22
    if any(amt in [7, 12, 17, 22] for amt in rotation_amounts):
        return "MD5 (signature rotations)"
    
    return "unknown_arx_cipher"


def _analyze_data_mixing(func, project) -> Dict[str, Any]:
    """
    Detect complex data mixing - multiple different operations on same data.
    
    Crypto mixes data through:
    - XOR + ADD + ROT (ARX)
    - Substitution + Permutation (SPN)
    - Multiple transformations in sequence
    """
    try:
        block = project.factory.block(func.addr, size=min(func.size, 500))
        instructions = block.capstone.insns
        
        operation_counts = {
            "xor": 0,
            "add": 0,
            "sub": 0,
            "mul": 0,
            "rotate": 0,
            "shift": 0,
            "and": 0,
            "or": 0
        }
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            
            # XOR: x86 (xor), ARM64 (eor), MIPS (xor)
            if 'xor' in mnemonic or mnemonic.startswith('eor'):
                operation_counts["xor"] += 1
            elif 'add' in mnemonic:
                operation_counts["add"] += 1
            elif 'sub' in mnemonic:
                operation_counts["sub"] += 1
            elif 'mul' in mnemonic or 'imul' in mnemonic:
                operation_counts["mul"] += 1
            # Rotations: x86 (rol, ror), ARM64 (ror, rorv)
            elif 'rol' in mnemonic or 'ror' in mnemonic:
                operation_counts["rotate"] += 1
            # Shifts: x86 (shl, shr), ARM64 (lsl, lsr, asr)
            elif any(x in mnemonic for x in ['shl', 'shr', 'shift', 'lsl', 'lsr', 'asr']):
                operation_counts["shift"] += 1
            elif 'and' in mnemonic:
                operation_counts["and"] += 1
            elif 'or' in mnemonic or mnemonic.startswith('orr'):  # ARM64 uses 'orr'
                operation_counts["or"] += 1
        
        # Count distinct operation types used
        distinct_ops = sum(1 for count in operation_counts.values() if count > 0)
        total_ops = sum(operation_counts.values())
        
        # Crypto mixing typically uses 3+ different operation types
        if distinct_ops >= 3 and total_ops >= 10:
            mixing_score = (distinct_ops * total_ops) / 100
            
            return {
                "function": func.name,
                "address": hex(func.addr),
                "operation_diversity": distinct_ops,
                "total_operations": total_ops,
                "operation_breakdown": operation_counts,
                "mixing_score": round(mixing_score, 2),
                "crypto_indicator": "very_strong" if mixing_score > 5 else "strong",
                "pattern_type": _classify_mixing_pattern(operation_counts)
            }
    except Exception as e:
        logger.debug(f"Error analyzing mixing in {func.name}: {e}")
    
    return None


def _classify_mixing_pattern(op_counts: Dict[str, int]) -> str:
    """Classify mixing pattern based on operation types"""
    # ARX: high ADD, XOR, ROTATE
    if op_counts["add"] >= 3 and op_counts["xor"] >= 3 and op_counts["rotate"] >= 2:
        return "ARX_cipher (ChaCha20/Salsa20 style)"
    
    # SPN: high XOR, shifts, AND/OR (for permutations)
    elif op_counts["xor"] >= 4 and (op_counts["shift"] + op_counts["rotate"]) >= 3:
        return "SPN_cipher (AES style)"
    
    # Hash function: diverse operations including AND/OR for bit manipulation
    elif op_counts["xor"] >= 3 and op_counts["and"] >= 2 and op_counts["or"] >= 2:
        return "hash_function (SHA/MD5 style)"
    
    # General crypto mixing
    else:
        return "general_crypto_mixing"


def _calculate_crypto_likelihood(patterns: Dict[str, Any]) -> float:
    """
    Calculate overall likelihood that this binary contains crypto based on dataflow.
    
    Score: 0.0 - 1.0
    - 0.9+: Very likely crypto
    - 0.7-0.9: Likely crypto
    - 0.5-0.7: Possible crypto
    - <0.5: Unlikely crypto
    """
    score = 0.0
    
    # XOR chains (strong indicator)
    xor_score = min(len(patterns["xor_chains"]) * 0.15, 0.4)
    score += xor_score
    
    # Bit rotations (moderate indicator)
    rotation_score = min(len(patterns["bit_rotations"]) * 0.12, 0.3)
    score += rotation_score
    
    # Data mixing (strong indicator)
    mixing_score = min(len(patterns["data_mixing"]) * 0.18, 0.4)
    score += mixing_score
    
    # CRITICAL FIX: Binary-wide aggregation bonus for stripped binaries
    # If we find crypto patterns across MANY functions (even if weak per-function),
    # it suggests inlined/optimized crypto spread across the binary
    total_patterns = len(patterns["xor_chains"]) + len(patterns["bit_rotations"]) + len(patterns["data_mixing"])
    if total_patterns >= 10:
        # Strong evidence: 10+ functions with crypto patterns = likely stripped crypto
        score += 0.3
    elif total_patterns >= 5:
        # Moderate evidence
        score += 0.15
    
    # Cap at 1.0
    return min(score, 1.0)


def _assess_crypto_characteristics(score: float) -> str:
    """Assess crypto characteristics based on score"""
    if score >= 0.9:
        return "Very strong crypto characteristics - highly likely contains cryptographic code"
    elif score >= 0.7:
        return "Strong crypto characteristics - likely contains cryptographic code"
    elif score >= 0.5:
        return "Moderate crypto characteristics - possibly contains cryptographic code"
    elif score >= 0.3:
        return "Weak crypto characteristics - may contain some crypto operations"
    else:
        return "Minimal crypto characteristics - unlikely to contain significant cryptographic code"
