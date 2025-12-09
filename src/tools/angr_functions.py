"""
Angr tool for extracting function information from binaries.
Enhanced with cyclomatic complexity filtering and YARA tag integration.
"""

import os
from typing import Dict, Any, Optional
import sys
import io
from contextlib import contextmanager
from .angr_loader_helper import load_binary_with_fallback, is_blob_loaded

try:
    import angr
    import networkx as nx
    import logging
    # Suppress verbose Angr output
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('pyvex').setLevel(logging.ERROR)
    os.environ['ANGR_PROGRESS_DISABLED'] = '1'
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


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

from src.utils.logger import get_logger

logger = get_logger(__name__)


def calculate_cyclomatic_complexity(func) -> int:
    """
    Calculate cyclomatic complexity of a function.
    Complexity = Edges - Nodes + 2 (for connected graph)
    
    Args:
        func: Angr Function object
        
    Returns:
        Cyclomatic complexity score
    """
    try:
        # Build control flow graph
        graph = func.transition_graph
        if graph is None or graph.number_of_nodes() == 0:
            return 0
        
        # Cyclomatic complexity formula: E - N + 2P
        # For a connected graph, P=1, so: E - N + 2
        edges = graph.number_of_edges()
        nodes = graph.number_of_nodes()
        complexity = edges - nodes + 2
        
        return max(complexity, 0)  # Ensure non-negative
    except Exception as e:
        logger.debug(f"Failed to calculate complexity: {e}")
        # Fallback: use basic block count as proxy
        return len(list(func.blocks))


def angr_extract_functions(
    binary_path: str,
    limit: int = 50,
    min_complexity: Optional[int] = None,
    yara_tags: Optional[Dict[int, list]] = None
) -> Dict[str, Any]:
    """
    Extract function information from binary using Angr's CFG analysis.
    Enhanced with complexity filtering and YARA tag integration.
    
    Args:
        binary_path: Path to the binary file
        limit: Maximum number of functions to return
        min_complexity: Minimum cyclomatic complexity to include function (default from env)
        yara_tags: Optional dict mapping function addresses to YARA tag lists
        
    Returns:
        Dict containing function information or error message
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        # Get complexity threshold from environment or parameter
        if min_complexity is None:
            min_complexity = int(os.getenv('MIN_FUNCTION_COMPLEXITY', '3'))
        
        logger.info(f"Extracting functions with min_complexity={min_complexity}")
        
        # Use blob loader fallback for raw binaries
        project = load_binary_with_fallback(binary_path, auto_load_libs=False)
        
        # Check if loaded as blob (raw binary)
        is_raw_binary = is_blob_loaded(project)
        if is_raw_binary:
            # For blobs: Use direct function discovery + targeted CFG for top functions
            min_complexity = 1
            logger.info(f"⚠️ Loaded as raw binary (blob), using smart function discovery")
            
            # Step 1: Get all auto-discovered functions (instant)
            logger.info("⚡ Step 1: Getting auto-discovered functions...")
            all_functions = project.kb.functions
            
            if len(all_functions) == 0:
                logger.warning("No functions auto-discovered, using entry point only")
                functions = [{
                    "address": hex(project.entry),
                    "name": "entry_point",
                    "size": 0,
                    "num_blocks": 0,
                    "cyclomatic_complexity": 1,
                    "calls_crypto_apis": False,
                    "yara_tags": [],
                    "has_yara_hit": False,
                    "complexity_score": 0
                }]
                return {
                    "total_functions": 1,
                    "functions": functions,
                    "analyzed_count": 1,
                    "filtered_count": 0,
                    "min_complexity_threshold": min_complexity,
                    "fast_mode": True
                }
            
            logger.info(f"✅ Found {len(all_functions)} auto-discovered functions")
            
            # Step 2: Filter to top candidates based on YARA hits and size
            logger.info("⚡ Step 2: Filtering to crypto-relevant candidates...")
            candidates = []
            for addr, func in list(all_functions.items())[:200]:  # Check first 200
                has_yara = yara_tags and addr in yara_tags if yara_tags else False
                size = func.size if hasattr(func, 'size') else 0
                
                # Prioritize: YARA hits OR larger functions (likely crypto)
                if has_yara or size >= 100:  # 100 bytes = decent sized function
                    candidates.append((addr, func, has_yara))
                
                if len(candidates) >= 20:  # Get top 20 candidates
                    break
            
            logger.info(f"✅ Found {len(candidates)} crypto-relevant candidates")
            
            # Step 3: Quick targeted CFG for just these candidates (10-15s)
            logger.info(f"⚡ Step 3: Building targeted CFG for {len(candidates)} functions...")
            function_addrs = [addr for addr, _, _ in candidates]
            
            try:
                import signal
                def timeout_handler(signum, frame):
                    raise TimeoutError("Targeted CFG timeout")
                
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(20)  # 20s max for targeted CFG
                
                with suppress_stdout():
                    cfg = project.analyses.CFGFast(
                        normalize=False,
                        force_complete_scan=False,
                        resolve_indirect_jumps=False,
                        data_references=False,
                        cross_references=False,
                        function_starts=function_addrs[:10]  # Only analyze top 10
                    )
                signal.alarm(0)
                logger.info("✅ Targeted CFG complete")
                cfg_functions = cfg.functions
            except (TimeoutError, Exception) as e:
                signal.alarm(0)
                logger.warning(f"⚠️ Targeted CFG failed ({e}), using basic function info")
                # Fallback: Use the auto-discovered functions with limited info
                cfg_functions = {addr: func for addr, func, _ in candidates}
        else:
            # For structured binaries: Use normal CFG
            with suppress_stdout():
                cfg = project.analyses.CFGFast(
                    normalize=True,
                    force_complete_scan=False,
                    resolve_indirect_jumps=False,
                    data_references=False,
                    cross_references=False
                )
            cfg_functions = cfg.functions
        functions = []
        filtered_count = 0
        total_analyzed = 0  # Track how many we analyzed
        max_to_analyze = 100 if is_raw_binary else 300  # Analyze more to find crypto-relevant ones
        max_functions = 10  # Only return top 10 functions
        
        for addr, func in cfg_functions.items():
            total_analyzed += 1
            
            # Early exit for blob binaries to prevent excessive analysis time
            if is_raw_binary and total_analyzed > max_to_analyze:
                logger.warning(f"⚠️ Blob binary: stopped after analyzing {total_analyzed} functions (limit: {max_to_analyze})")
                break
            
            # Skip PLT and simprocedures (library stubs)
            if func.is_simprocedure or func.is_plt:
                continue
            
            # Calculate complexity
            complexity = calculate_cyclomatic_complexity(func)
            num_blocks = len(list(func.blocks))
            
            # Check if function has YARA hits
            has_yara_hit = False
            func_yara_tags = []
            if yara_tags and addr in yara_tags:
                has_yara_hit = True
                func_yara_tags = yara_tags[addr]
            
            # Smart filtering for blobs: Keep if (complexity >= 3) OR (has YARA hit)
            # This ensures we only get crypto-relevant functions
            if is_raw_binary:
                # For blobs: Only keep functions with YARA hits OR complexity >= 3
                if not has_yara_hit and complexity < 3:
                    filtered_count += 1
                    continue
            else:
                # For structured binaries: Use normal threshold
                if complexity < min_complexity and not has_yara_hit:
                    filtered_count += 1
                    continue
            
            # Include this function
            func_info = {
                "address": hex(addr),
                "name": func.name,
                "size": func.size,
                "num_blocks": num_blocks,
                "cyclomatic_complexity": complexity,
                "calls_crypto_apis": False,  # TODO: Detect crypto API calls
                "yara_tags": func_yara_tags,
                "has_yara_hit": has_yara_hit,
                "complexity_score": round(complexity / max(num_blocks, 1), 2)
            }
            
            functions.append(func_info)
            
            # Stop if we have enough functions
            if len(functions) >= max_functions:
                logger.info(f"✅ Collected {max_functions} crypto-relevant functions, stopping early")
                break
            
            if len(functions) >= limit:
                break
        
        # Sort by priority: YARA hits first, then by complexity
        functions.sort(key=lambda f: (not f['has_yara_hit'], -f['cyclomatic_complexity']))
        
        # Limit to top 10 functions
        if len(functions) > max_functions:
            logger.info(f"📊 Keeping top {max_functions} most relevant functions (out of {len(functions)})")
            functions = functions[:max_functions]
        
        logger.info(f"✅ Extracted {len(functions)} functions (filtered out {filtered_count} low-complexity)")
        
        return {
            "total_functions": len(cfg_functions) if cfg_functions else 0,
            "functions": functions,
            "analyzed_count": len(functions),
            "filtered_count": filtered_count,
            "min_complexity_threshold": min_complexity
        }
    except Exception as e:
        logger.error(f"Failed to extract functions: {e}", exc_info=True)
        return {"error": f"Failed to extract functions: {str(e)}"}
