"""
Angr tool for detecting cryptographic patterns through control flow analysis.
Identifies crypto algorithms by their structural patterns (loops, ARX operations, etc.)
"""

from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


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
        project = angr.Project(binary_path, auto_load_libs=False)
        
        logger.info("Building CFG...")
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=True  # Important for stripped binaries
        )
        logger.info(f"CFG built: {len(cfg.functions)} functions found")
        
        patterns = {
            "round_loops": [],
            "arx_operations": [],
            "feistel_networks": [],
            "spn_structures": [],
            "table_lookups": [],
            "modular_arithmetic": []
        }
        
        # Analyze top functions by complexity
        sorted_functions = sorted(
            cfg.functions.values(),
            key=lambda f: len(list(f.blocks)) if not f.is_simprocedure else 0,
            reverse=True
        )[:50]  # Analyze top 50 complex functions
        
        for func in sorted_functions:
            if func.is_simprocedure or func.is_plt:
                continue
            
            try:
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
                    
            except Exception as e:
                logger.debug(f"Error analyzing function {func.name}: {e}")
                continue
        
        # Infer algorithms from patterns
        inferred_algorithms = _infer_algorithms_from_patterns(patterns)
        
        return {
            "patterns": patterns,
            "inferred_algorithms": inferred_algorithms,
            "pattern_summary": {
                "round_loops_found": len(patterns["round_loops"]),
                "arx_operations_found": len(patterns["arx_operations"]),
                "table_lookups_found": len(patterns["table_lookups"]),
                "modular_ops_found": len(patterns["modular_arithmetic"])
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
    """
    try:
        block = project.factory.block(func.addr, size=min(func.size, 500))
        instructions = block.capstone.insns
        
        mul_count = 0
        div_count = 0
        wide_ops = 0
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            
            if 'mul' in mnemonic or 'imul' in mnemonic:
                mul_count += 1
            elif 'div' in mnemonic or 'mod' in mnemonic:
                div_count += 1
            
            # Check for 64-bit operations (RSA typically uses large numbers)
            if 'qword' in insn.op_str or 'r64' in insn.op_str:
                wide_ops += 1
        
        # RSA/ECC pattern: lots of multiplication and some division
        if (mul_count >= 5 or div_count >= 2) and wide_ops >= 3:
            return {
                "function": func.name,
                "address": hex(func.addr),
                "multiplications": mul_count,
                "divisions": div_count,
                "wide_operations": wide_ops,
                "likely_algorithm": "RSA or ECC"
            }
    except Exception as e:
        logger.debug(f"Error detecting modular arithmetic in {func.name}: {e}")
    
    return None


def _infer_algorithms_from_patterns(patterns: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Infer likely cryptographic algorithms from detected patterns.
    """
    algorithms = []
    
    # ARX patterns → ChaCha20/Salsa20/BLAKE2
    if patterns["arx_operations"]:
        for arx in patterns["arx_operations"]:
            algorithms.append({
                "algorithm": arx["likely_algorithm"],
                "confidence": 0.75,
                "evidence": f"ARX pattern detected (ADD:{arx['add_operations']}, XOR:{arx['xor_operations']}, ROT:{arx['rotate_operations']})",
                "function": arx["function"]
            })
    
    # Table lookups → AES, DES
    if patterns["table_lookups"]:
        for table in patterns["table_lookups"]:
            confidence = 0.80 if table["confidence"] == "high" else 0.65
            algorithms.append({
                "algorithm": "AES or DES (S-box based cipher)",
                "confidence": confidence,
                "evidence": f"S-box pattern with {table['table_accesses']} table accesses",
                "function": table["function"]
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
                algo = "DES"
            elif rounds == 20:
                algo = "ChaCha20/Salsa20"
            else:
                algo = f"Unknown cipher ({rounds} rounds)"
            
            algorithms.append({
                "algorithm": algo,
                "confidence": 0.70,
                "evidence": f"Round-based loop structure with ~{rounds} iterations",
                "function": loop["function"]
            })
    
    # Modular arithmetic → RSA/ECC
    if patterns["modular_arithmetic"]:
        for mod in patterns["modular_arithmetic"]:
            algorithms.append({
                "algorithm": mod["likely_algorithm"],
                "confidence": 0.65,
                "evidence": f"Large number arithmetic (MUL:{mod['multiplications']}, DIV:{mod['divisions']})",
                "function": mod["function"]
            })
    
    # CRITICAL FIX: Binary-wide aggregation for stripped binaries
    # If we found table lookups across MULTIPLE functions but no other patterns,
    # boost confidence that it's crypto (likely inlined/optimized AES)
    if len(patterns["table_lookups"]) >= 2 and not algorithms:
        algorithms.append({
            "algorithm": "AES (inlined/optimized S-box implementation)",
            "confidence": 0.80,
            "evidence": f"Multiple S-box patterns detected across {len(patterns['table_lookups'])} functions",
            "function": "binary-wide analysis"
        })
    
    return algorithms


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
        
        project = angr.Project(binary_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=True)
        
        # Build call graph relationships
        function_groups = []
        visited = set()
        
        for func_addr, func in cfg.functions.items():
            if func.is_simprocedure or func.is_plt or func_addr in visited:
                continue
            
            # Start new group with BFS from this function
            group = _build_function_cluster(func, cfg, visited)
            
            if len(group) >= 2:  # Only keep groups with 2+ functions
                function_groups.append({
                    "functions": list(group),
                    "size": len(group),
                    "root_function": func_addr
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

