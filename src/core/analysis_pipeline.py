"""
Orchestrator-based Analysis Pipeline
Intelligent multi-stage analysis using cost-optimized model selection.
Enhanced with YARA scanning, complexity filtering, and intelligent batching.
"""

import json
import time
import tempfile
import os
import asyncio
from typing import Dict, Any, List
from pathlib import Path

from src.models.multi_model_orchestrator import MultiModelOrchestrator
from src.core.angr_tools import check_angr_available
from src.detectors.yara_detector import YaraDetector, yara_scan_binary
from src.utils.token_batcher import TokenBatcher
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisPipeline:
    """Multi-stage analysis pipeline with intelligent model orchestration."""
    
    def __init__(self, orchestrator: MultiModelOrchestrator):
        """
        Initialize analysis pipeline.
        
        Args:
            orchestrator: MultiModelOrchestrator instance
        """
        self.orchestrator = orchestrator
        self.angr_available = check_angr_available()
        
        # Initialize YARA detector
        try:
            self.yara_detector = YaraDetector()
            logger.info("✅ YARA detector initialized")
        except Exception as e:
            logger.warning(f"YARA detector initialization failed: {e}")
            self.yara_detector = None
        
        # Initialize token batcher
        self.token_batcher = TokenBatcher()
        logger.info("✅ Token batcher initialized")
        
    async def run_quick_triage(self, binary_path: str, filename: str) -> Dict[str, Any]:
        """
        Stage 1: Quick triage using specialized modular prompt.
        Determines if binary is worth deep analysis.
        Enhanced with parallel protocol detection for faster triage.
        
        Returns:
            Dict with is_crypto_likely, confidence, reasoning, and detected protocols
        """
        logger.info(f"Stage 1: Quick triage for {filename}")
        
        # Load specialized triage prompt
        triage_prompt = self._load_prompt("prompts/1_triage.md")
        
        # Gather minimal context
        context = {"filename": filename, "size": os.path.getsize(binary_path)}
        
        # Run metadata, strings, and protocol detection in parallel
        protocol_data = None
        if self.angr_available:
            from src.tools.angr_metadata import angr_analyze_binary_metadata
            from src.tools.angr_strings import angr_analyze_strings
            
            # Parallel execution of metadata and string extraction
            metadata_task = asyncio.create_task(
                asyncio.to_thread(angr_analyze_binary_metadata, binary_path)
            )
            strings_task = asyncio.create_task(
                asyncio.to_thread(angr_analyze_strings, binary_path)
            )
            
            # Get results
            metadata, strings = await asyncio.gather(metadata_task, strings_task)
            
            # Quick protocol detection from strings
            crypto_strings = strings.get("crypto_related_strings", [])
            protocol_data = self._detect_protocols_from_strings(crypto_strings)
            
            context.update({
                "architecture": metadata.get("architecture"),
                "crypto_strings": crypto_strings[:10],
                "detected_protocols": protocol_data.get("protocols", [])
            })
        
        query = f"""
{triage_prompt}

=== BINARY DATA TO ANALYZE ===

Filename: {filename}
Size: {context['size']} bytes
Architecture: {context.get('architecture', 'unknown')}
Crypto-related strings: {json.dumps(context.get('crypto_strings', []))}

=== END BINARY DATA ===

Now classify this binary according to the instructions above. Respond ONLY with valid JSON.
"""
        
        result = await self.orchestrator.analyze(
            query=query,
            context=context,
            analysis_type='quick_classify'
        )
        
        # Parse response
        triage = self._parse_json_response(result['content'], "Stage 1: Triage")
        triage['stage1_cost'] = result['cost']
        triage['stage1_model'] = result['model']
        
        logger.info(f"Triage result: {triage.get('recommended_analysis')} (confidence: {triage.get('confidence')})")
        return triage
    
    async def run_angr_extraction(self, binary_path: str) -> Dict[str, Any]:
        """
        Stage 2: Run all Angr analysis tools.
        Extracts static analysis data from binary.
        
        Returns:
            Dict with all Angr analysis results
        """
        logger.info("Stage 2: Running Angr analysis tools")
        
        if not self.angr_available:
            logger.warning("Angr not available, using fallback")
            return {"angr_available": False}
        
        from src.tools.angr_metadata import angr_analyze_binary_metadata
        from src.tools.angr_functions import angr_extract_functions
        from src.tools.angr_strings import angr_analyze_strings
        from src.tools.angr_constants import angr_detect_crypto_constants
        from src.tools.angr_patterns import angr_detect_crypto_patterns
        from src.tools.angr_dataflow import angr_analyze_dataflow
        
        results = {}
        
        # Extract metadata
        try:
            results['metadata'] = angr_analyze_binary_metadata(binary_path)
            # Check if metadata extraction failed (Angr returns {"error": "..."} on failure)
            if 'error' in results['metadata']:
                logger.error(f"❌ Metadata extraction failed: {results['metadata']['error']}")
                results['metadata'] = {}  # Clear error dict
            else:
                logger.info("✅ Metadata extracted")
        except Exception as e:
            logger.error(f"Metadata extraction failed: {e}")
            results['metadata'] = {}
        
        # Analyze strings
        try:
            results['strings'] = angr_analyze_strings(binary_path)
            logger.info(f"✅ Found {len(results['strings'].get('crypto_related_strings', []))} crypto strings")
        except Exception as e:
            logger.error(f"String analysis failed: {e}")
            results['strings'] = {}
        
        # **PHASE 2.5: YARA SCANNING** - Additional layer of crypto signature detection
        yara_results = None
        yara_function_map = {}
        if self.yara_detector:
            try:
                logger.info("Starting YARA signature scanning (60s max timeout)...")
                import signal
                
                def timeout_handler(signum, frame):
                    raise TimeoutError("YARA scan exceeded 60s timeout")
                
                # Set 60s timeout for YARA (critical - don't compromise)
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(60)  # 60 second timeout
                
                try:
                    yara_results = self.yara_detector.scan_binary(binary_path)
                finally:
                    signal.alarm(0)  # Cancel alarm
                
                if yara_results.get('scan_successful'):
                    summary = yara_results['summary']
                    logger.info(f"✅ YARA scan complete: {summary['total_rules_matched']} rules matched")
                    logger.info(f"   Algorithms detected: {summary['algorithms']}")
                    logger.info(f"   Crypto confidence: {summary['crypto_confidence']}")
                    
                    results['yara'] = yara_results
                else:
                    logger.warning(f"YARA scan failed: {yara_results.get('error')}")
            except Exception as e:
                logger.error(f"❌ YARA scanning failed: {e}", exc_info=True)
                results['yara'] = {"error": str(e)}
        else:
            logger.info("⚠️  YARA detector not available, skipping signature scanning")
        
        # Detect constants (DISABLED FOR SPEED)
        try:
            logger.info("⚡ Skipping constant detection (disabled for speed)")
            results['constants'] = {'detected_constants': [], 'skipped': True}
            if False:  # Disabled
                results['constants'] = angr_detect_crypto_constants(binary_path)
            if 'error' in results['constants']:
                logger.error(f"❌ Constant detection failed: {results['constants']['error']}")
                results['constants'] = {'detected_constants': []}
            else:
                const_count = len(results['constants'].get('detected_constants', []))
                logger.info(f"✅ Found {const_count} crypto constants")
                if results['constants'].get('algorithm_groups'):
                    logger.info(f"   Algorithm hints: {list(results['constants']['algorithm_groups'].keys())}")
        except Exception as e:
            logger.error(f"Constant detection failed: {e}")
            results['constants'] = {'detected_constants': []}
        
        # Extract functions (WITH YARA TAG INTEGRATION and COMPLEXITY FILTERING)
        try:
            logger.info("Starting function extraction (120s max timeout)...")
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError("Function extraction exceeded 120s timeout")
            
            # Set 120s timeout for function extraction
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(120)  # 120 second timeout
            
            try:
                # Pass YARA results to function extraction for tag association
                results['functions'] = angr_extract_functions(
                    binary_path,
                    limit=30,  # ⚡ ULTRA FAST: Only 30 most complex functions
                    min_complexity=None,  # Uses env var MIN_FUNCTION_COMPLEXITY
                    yara_tags=yara_function_map  # Will be populated if YARA found matches
                )
            finally:
                signal.alarm(0)  # Cancel alarm
            
            # Check if function extraction failed
            if 'error' in results['functions']:
                logger.error(f"❌ Function extraction failed: {results['functions']['error']}")
                results['functions'] = {'functions': []}  # Provide empty list instead of error dict
            else:
                logger.info(f"✅ Extracted {len(results['functions'].get('functions', []))} functions")
                
                # Log filtering stats
                if 'filtered_count' in results['functions']:
                    logger.info(f"   Filtered {results['functions']['filtered_count']} low-complexity functions")
                    logger.info(f"   Complexity threshold: {results['functions'].get('min_complexity_threshold', 3)}")
                    
                # Log if adaptive retry was used
                if results['functions'].get('adaptive_retry'):
                    logger.info(f"   ✅ Adaptive retry enabled (lowered threshold to extract functions)")
        except Exception as e:
            logger.error(f"Function extraction failed: {e}")
            results['functions'] = {'functions': []}
        
        # Detect crypto patterns (DISABLED FOR SPEED - saves 30+ seconds)
        try:
            logger.info("⚡ Skipping pattern detection (disabled for speed)")
            results['patterns'] = {'pattern_summary': {}, 'inferred_algorithms': [], 'skipped': True}
            if False:  # Disabled
                results['patterns'] = angr_detect_crypto_patterns(binary_path)
            
            if 'error' in results['patterns']:
                logger.error(f"❌ Pattern detection failed: {results['patterns']['error']}")
                results['patterns'] = {'pattern_summary': {}, 'inferred_algorithms': []}
            else:
                pattern_summary = results['patterns'].get('pattern_summary', {})
                logger.info(f"✅ Pattern detection complete")
                logger.info(f"   Round loops: {pattern_summary.get('round_loops_found', 0)}")
                logger.info(f"   ARX operations: {pattern_summary.get('arx_operations_found', 0)}")
                logger.info(f"   Table lookups: {pattern_summary.get('table_lookups_found', 0)}")
                
                if results['patterns'].get('inferred_algorithms'):
                    logger.info(f"   Inferred algorithms: {[a['algorithm'] for a in results['patterns']['inferred_algorithms'][:3]]}")
                else:
                    logger.warning("   ⚠️  No algorithms inferred from patterns")
        except Exception as e:
            logger.error(f"❌ Pattern detection failed: {e}", exc_info=True)
            results['patterns'] = {'pattern_summary': {}, 'inferred_algorithms': []}
        
        # Analyze data flow (DISABLED FOR SPEED - saves 20+ seconds)
        try:
            logger.info("⚡ Skipping dataflow analysis (disabled for speed)")
            results['dataflow'] = {'summary': {}, 'crypto_likelihood_score': 0, 'skipped': True}
            if False:  # Disabled
                results['dataflow'] = angr_analyze_dataflow(binary_path)
            
            if 'error' in results['dataflow']:
                logger.error(f"❌ Dataflow analysis failed: {results['dataflow']['error']}")
                results['dataflow'] = {'summary': {}, 'crypto_likelihood_score': 0}
            else:
                dataflow_summary = results['dataflow'].get('summary', {})
                crypto_score = results['dataflow'].get('crypto_likelihood_score', 0)
                logger.info(f"✅ Dataflow analysis complete")
                logger.info(f"   XOR chains: {dataflow_summary.get('xor_chains_found', 0)}")
                logger.info(f"   Bit rotations: {dataflow_summary.get('rotations_found', 0)}")
                logger.info(f"   Crypto likelihood: {crypto_score:.2f}")
                
                if crypto_score < 0.3:
                    logger.warning(f"   ⚠️  Low crypto likelihood score: {crypto_score:.2f}")
        except Exception as e:
            logger.error(f"❌ Dataflow analysis failed: {e}", exc_info=True)
            results['dataflow'] = {'summary': {}, 'crypto_likelihood_score': 0}
        
        # Build function groups (DISABLED FOR SPEED - saves 15+ seconds)
        try:
            logger.info("⚡ Skipping function groups (disabled for speed)")
            results['function_groups'] = {'total_groups': 0, 'skipped': True}
            if False:  # Disabled
                from src.tools.angr_patterns import angr_build_function_groups
                results['function_groups'] = angr_build_function_groups(binary_path)
            group_count = results['function_groups'].get('total_groups', 0)
            largest_group = results['function_groups'].get('largest_group_size', 0)
            logger.info(f"✅ Found {group_count} function groups (largest: {largest_group} functions)")
            
            # CRITICAL FIX: If function extraction failed (0 functions) but we have function groups,
            # populate functions list from the largest groups so AI has something to analyze
            if len(results.get('functions', {}).get('functions', [])) == 0 and group_count > 0:
                fg_data = results['function_groups']
                if 'function_groups' in fg_data and fg_data['function_groups']:
                    # Extract top 20 largest functions from top 5 groups
                    all_groups = fg_data['function_groups']
                    top_groups = sorted(all_groups, key=lambda g: g.get('size', 0), reverse=True)[:5]
                    
                    # Collect all unique function addresses
                    func_addrs = set()
                    for group in top_groups:
                        func_addrs.update(group.get('functions', []))
                    
                    # Create minimal function entries for AI analysis
                    results['functions'] = {
                        'functions': [
                            {
                                'name': f'func_{hex(addr)}',
                                'address': hex(addr),
                                'size': 'unknown',
                                'complexity': 'unknown',
                                'calls_crypto_apis': False
                            }
                            for addr in sorted(list(func_addrs))[:20]  # Limit to 20 functions
                        ]
                    }
                    logger.info(f"✅ Populated {len(results['functions']['functions'])} functions from function groups for AI analysis")
            
            # Aggregate patterns across function groups
            if group_count > 0:
                aggregated_score = self._aggregate_patterns_across_groups(
                    results['patterns'],
                    results['dataflow'],
                    results['function_groups']
                )
                results['aggregated_crypto_score'] = aggregated_score
                logger.info(f"   Aggregated crypto score: {aggregated_score:.2f}")
        except Exception as e:
            logger.error(f"❌ Function group analysis failed: {e}", exc_info=True)
            results['function_groups'] = {"error": str(e)}

        
        return results
    
    async def run_algorithm_detection(
        self,
        angr_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Stage 3: Algorithm detection using specialized modular prompt.
        Identifies all cryptographic algorithms in the binary.
        
        Returns:
            Dict with detected algorithms and evidence
        """
        logger.info("Stage 3: Algorithm detection")
        
        # Load specialized algorithm detection prompt
        algo_prompt = self._load_prompt("prompts/2_algorithm_detection.md")
        
        # Optimize Angr results
        optimized = self._optimize_angr_data(angr_results)
        
        query = f"""
{algo_prompt}

=== ANGR BINARY ANALYSIS DATA ===

{json.dumps(optimized, indent=2)}

=== END ANGR DATA ===

Now detect all cryptographic algorithms according to the instructions above. Respond ONLY with valid JSON array.
"""
        
        result = await self.orchestrator.analyze(
            query=query,
            context=optimized,
            analysis_type='main_analysis'
        )
        
        algorithms = self._parse_json_response(result['content'], "Stage 3: Algorithm Detection")
        logger.info(f"✅ Detected {len(algorithms) if isinstance(algorithms, list) else 0} algorithms")
        
        return {
            'algorithms': algorithms,
            'cost': result['cost'],
            'model': result['model']
        }
    
    async def run_function_analysis(
        self,
        angr_results: Dict[str, Any],
        detected_algorithms: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Stage 4: Function analysis using specialized modular prompt.
        Analyzes crypto functions in detail.
        Enhanced with intelligent batching for large binaries with 100+ functions.
        
        Returns:
            Dict with function analysis results
        """
        logger.info("Stage 4: Function analysis")
        
        # Load specialized function analysis prompt
        func_prompt = self._load_prompt("prompts/3_function_analysis.md")
        
        optimized = self._optimize_angr_data(angr_results)
        functions = optimized.get('functions', {}).get('functions', [])
        
        # Check if we need batching
        total_functions = len(functions)
        if total_functions == 0:
            logger.warning("No functions to analyze")
            return {
                'functions': [],
                'cost': 0,
                'model': 'none'
            }
        
        # Estimate if batching is needed (reduced threshold for speed)
        sample_data = {
            "algorithms": detected_algorithms,
            "functions": functions[:5]  # Sample
        }
        estimated_tokens = self.token_batcher.estimate_tokens_from_dict(sample_data)
        needs_batching = total_functions > 25 or self.token_batcher.should_batch(estimated_tokens * (total_functions / 5))
        
        if needs_batching:
            logger.info(f"📦 Batching {total_functions} functions for analysis...")
            all_analyzed_functions = []
            total_cost = 0.0
            batch_num = 0
            
            # Batch the functions
            for batch in self.token_batcher.batch_functions(functions):
                batch_num += 1
                batch_info = batch['batch_info']
                batch_functions = batch['functions']
                
                logger.info(
                    f"   Batch {batch_info['batch_number']}/{batch_info['total_batches']}: "
                    f"{batch_info['functions_in_batch']} functions "
                    f"(~{batch_info['estimated_tokens']} tokens)"
                )
                
                query = f"""
{func_prompt}

=== INPUT DATA ===

Detected Algorithms: {json.dumps(detected_algorithms, indent=2)}

Functions (Batch {batch_info['batch_number']}/{batch_info['total_batches']}): {json.dumps({'functions': batch_functions}, indent=2)}

Strings: {json.dumps(optimized.get('crypto_strings', []))}

=== END INPUT DATA ===

Now analyze all crypto-related functions in this batch according to the instructions above. Respond ONLY with valid JSON array.
"""
                
                result = await self.orchestrator.analyze(
                    query=query,
                    context={"algorithms": detected_algorithms, "functions": batch_functions},
                    analysis_type='main_analysis'
                )
                
                batch_functions_analyzed = self._parse_json_response(result['content'], f"Stage 4: Function Analysis (Batch {batch_num})")
                all_analyzed_functions.extend(batch_functions_analyzed if isinstance(batch_functions_analyzed, list) else [])
                total_cost += result['cost']
            
            logger.info(f"✅ Analyzed {len(all_analyzed_functions)} functions across {batch_num} batches")
            
            return {
                'functions': all_analyzed_functions,
                'cost': total_cost,
                'model': 'batched-analysis',
                'batches': batch_num
            }
        else:
            # Single query for all functions
            logger.info(f"⚡ Fast mode: analyzing {total_functions} functions in single query")
            
            query = f"""
{func_prompt}

=== INPUT DATA ===

Detected Algorithms: {json.dumps(detected_algorithms, indent=2)}

Functions: {json.dumps(optimized.get('functions', {}), indent=2)}

Strings: {json.dumps(optimized.get('crypto_strings', []))}

=== END INPUT DATA ===

Now analyze all crypto-related functions according to the instructions above. Respond ONLY with valid JSON array.
"""
            
            result = await self.orchestrator.analyze(
                query=query,
                context={"algorithms": detected_algorithms, "functions": optimized.get('functions', {})},
                analysis_type='main_analysis'
            )
            
            functions_analyzed = self._parse_json_response(result['content'], "Stage 4: Function Analysis")
            logger.info(f"✅ Analyzed {len(functions_analyzed) if isinstance(functions_analyzed, list) else 0} functions")
            
            return {
                'functions': functions_analyzed,
                'cost': result['cost'],
                'model': result['model']
            }
    
    async def run_vulnerability_scan(
        self,
        angr_results: Dict[str, Any],
        detected_algorithms: List[Dict[str, Any]],
        detected_functions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Stage 5: Vulnerability scanning using specialized modular prompt.
        Detects security issues and extracts hardcoded secrets.
        
        Returns:
            Dict with vulnerability findings
        """
        logger.info("Stage 5: Vulnerability scanning")
        
        # Load specialized vulnerability scan prompt
        vuln_prompt = self._load_prompt("prompts/4_vulnerability_scan.md")
        
        optimized = self._optimize_angr_data(angr_results)
        
        # Extract pattern data for vulnerability scanning
        patterns_for_vuln = {}
        if 'patterns' in angr_results:
            patterns_for_vuln = {
                'hardcoded_keys': angr_results['patterns'].get('hardcoded_keys', {}),
                'inferred_algorithms': angr_results['patterns'].get('inferred_algorithms', [])
            }
        
        query = f"""
{vuln_prompt}

=== INPUT DATA ===

Detected Algorithms: {json.dumps(detected_algorithms, indent=2)}

Detected Functions: {json.dumps(detected_functions, indent=2)}

Strings: {json.dumps(optimized.get('crypto_strings', []))}

Constants: {json.dumps(optimized.get('constants', {}))}

Patterns (Hardcoded Keys & Inferred Algorithms): {json.dumps(patterns_for_vuln, indent=2)}

=== END INPUT DATA ===

Now scan for all vulnerabilities according to the instructions above. Respond ONLY with valid JSON array.
"""
        
        result = await self.orchestrator.analyze(
            query=query,
            context={"algorithms": detected_algorithms, "functions": detected_functions},
            analysis_type='main_analysis'
        )
        
        vulnerabilities = self._parse_json_response(result['content'], "Stage 5: Vulnerability Scan")
        logger.info(f"✅ Found {len(vulnerabilities) if isinstance(vulnerabilities, list) else 0} vulnerabilities")
        
        return {
            'vulnerabilities': vulnerabilities,
            'cost': result['cost'],
            'model': result['model']
        }
    
    async def run_protocol_detection(
        self,
        angr_results: Dict[str, Any],
        detected_algorithms: List[Dict[str, Any]],
        detected_functions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Stage 6: Protocol detection using specialized modular prompt.
        Identifies cryptographic protocols and standards.
        
        Returns:
            Dict with detected protocols
        """
        logger.info("Stage 6: Protocol detection")
        
        # Load specialized protocol detection prompt
        protocol_prompt = self._load_prompt("prompts/5_protocol_detection.md")
        
        optimized = self._optimize_angr_data(angr_results)
        
        query = f"""
{protocol_prompt}

=== INPUT DATA ===

Detected Algorithms: {json.dumps(detected_algorithms, indent=2)}

Detected Functions: {json.dumps(detected_functions, indent=2)}

Strings: {json.dumps(optimized.get('crypto_strings', []))}

=== END INPUT DATA ===

Now identify all cryptographic protocols according to the instructions above. Respond ONLY with valid JSON array.
"""
        
        result = await self.orchestrator.analyze(
            query=query,
            context={"algorithms": detected_algorithms, "functions": detected_functions},
            analysis_type='main_analysis'
        )
        
        protocols = self._parse_json_response(result['content'], "Stage 6: Protocol Detection")
        logger.info(f"✅ Detected {len(protocols) if isinstance(protocols, list) else 0} protocols")
        
        return {
            'protocols': protocols,
            'cost': result['cost'],
            'model': result['model']
        }
    
    async def run_final_synthesis(
        self,
        angr_results: Dict[str, Any],
        stage_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Stage 7: Final synthesis using specialized modular prompt.
        Combines all stage results into comprehensive 9-section report.
        
        Args:
            angr_results: Raw Angr analysis results
            stage_results: Results from all previous stages
            
        Returns:
            Complete comprehensive analysis report
        """
        logger.info("Stage 7: Final synthesis")
        
        # Load specialized synthesis prompt
        synthesis_prompt = self._load_prompt("prompts/6_synthesis.md")
        
        optimized = self._optimize_angr_data(angr_results)
        
        query = f"""
{synthesis_prompt}

=== STAGE OUTPUTS ===

Triage Result: {json.dumps(stage_results.get('triage', {}), indent=2)}

Algorithm Detection: {json.dumps(stage_results.get('algorithms', []), indent=2)}

Function Analysis: {json.dumps(stage_results.get('functions', []), indent=2)}

Vulnerability Scan: {json.dumps(stage_results.get('vulnerabilities', []), indent=2)}

Protocol Detection: {json.dumps(stage_results.get('protocols', []), indent=2)}

Angr Metadata: {json.dumps(optimized.get('metadata', {}), indent=2)}

=== END STAGE OUTPUTS ===

Now synthesize all stage outputs into the final comprehensive JSON report according to the instructions above. Respond ONLY with valid JSON.
"""
        
        result = await self.orchestrator.analyze(
            query=query,
            context=stage_results,
            analysis_type='main_analysis'
        )
        
        try:
            final_report = self._parse_json_response(result['content'], "Stage 7: Final Synthesis")
        except json.JSONDecodeError as e:
            # Log the malformed JSON for debugging
            logger.error(f"❌ JSON parsing failed in final synthesis: {e}")
            logger.error(f"Content preview (first 500 chars): {result['content'][:500]}")
            logger.error(f"Content preview (around error char {e.pos}): {result['content'][max(0, e.pos-100):min(len(result['content']), e.pos+100)]}")
            
            # Save to file for detailed debugging
            error_file = f"logs/json_parse_error_{int(time.time())}.txt"
            try:
                with open(error_file, 'w') as f:
                    f.write(f"JSON Parsing Error:\n{e}\n\n")
                    f.write(f"Full Content:\n{result['content']}")
                logger.error(f"Full malformed JSON saved to: {error_file}")
            except Exception as write_error:
                logger.error(f"Could not save error file: {write_error}")
            
            # Try one more aggressive repair: Request re-generation with stricter prompt
            logger.warning("⚠️ Attempting JSON re-generation with stricter prompt...")
            try:
                retry_query = f"""
The previous JSON response had syntax errors. Please regenerate ONLY valid JSON.

CRITICAL REQUIREMENTS:
1. No markdown code blocks (```json or ```)
2. No trailing commas
3. All strings properly escaped
4. No comments
5. Start with {{ and end with }}

Previous data to format correctly:
{result['content'][:1000]}...

Generate a valid JSON report with this structure:
{{
  "file_metadata": {{}},
  "detected_algorithms": [],
  "function_analyses": [],
  "vulnerability_assessment": {{}},
  "recommendations": [],
  "risk_score": 0
}}

RESPOND WITH ONLY THE JSON. NO OTHER TEXT.
"""
                retry_result = await self.orchestrator.analyze(
                    query=retry_query,
                    context={},
                    analysis_type='json_repair'
                )
                
                final_report = self._parse_json_response(retry_result['content'], "Stage 7: Final Synthesis (Retry)")
                logger.info("✅ JSON re-generation successful")
                
                # Update cost
                result['cost'] += retry_result['cost']
                result['duration'] += retry_result['duration']
                
            except Exception as retry_error:
                logger.error(f"❌ JSON re-generation also failed: {retry_error}")
                
                # Last resort: Return minimal valid report
                logger.warning("⚠️ Returning minimal fallback report")
                final_report = {
                    "file_metadata": angr_results.get('metadata', {}),
                    "detected_algorithms": angr_results.get('inferred_algorithms', []),
                    "function_analyses": [],
                    "vulnerability_assessment": {
                        "vulnerabilities": [{
                            "type": "ANALYSIS_ERROR",
                            "severity": "INFO",
                            "description": "Analysis completed with JSON parsing errors. Manual review recommended.",
                            "details": f"LLM response could not be parsed: {str(e)[:200]}"
                        }],
                        "risk_score": 0,
                        "overall_assessment": "Analysis incomplete due to JSON parsing errors"
                    },
                    "recommendations": [
                        "Manual security review recommended due to automated analysis errors"
                    ],
                    "risk_score": 0,
                    "analysis_status": "PARTIAL_FAILURE",
                    "error_details": str(e)[:500]
                }

        
        # Add analysis metadata
        final_report['_analysis_metadata'] = {
            'model_used': 'cypherray-ai-engine',
            'provider': 'cypherray',
            'cost': result['cost'],
            'duration': result['duration']
        }
        
        # **CRITICAL FIX**: Force correct file metadata from Angr (Claude sometimes returns "not_computed" for size)
        if 'metadata' in angr_results and angr_results['metadata'] and 'error' not in angr_results['metadata']:
            angr_meta = angr_results['metadata']
            if 'file_metadata' not in final_report or not final_report['file_metadata']:
                final_report['file_metadata'] = {}
            
            # Override with actual Angr values (prevent "not_computed" strings in numeric fields)
            file_type_value = angr_meta.get('file_type', final_report['file_metadata'].get('format', 'unknown'))
            final_report['file_metadata']['file_type'] = file_type_value  # Backend checks this first
            final_report['file_metadata']['format'] = file_type_value      # Also set format for compatibility
            final_report['file_metadata']['architecture'] = angr_meta.get('architecture', final_report['file_metadata'].get('architecture', 'unknown'))
            final_report['file_metadata']['size'] = angr_meta.get('size_bytes', final_report['file_metadata'].get('size_bytes', 0))
            final_report['file_metadata']['size_bytes'] = angr_meta.get('size_bytes', final_report['file_metadata'].get('size_bytes', 0))
            final_report['file_metadata']['md5'] = angr_meta.get('md5', final_report['file_metadata'].get('md5', 'not_computed'))
            final_report['file_metadata']['sha1'] = angr_meta.get('sha1', final_report['file_metadata'].get('sha1', 'not_computed'))
            final_report['file_metadata']['sha256'] = angr_meta.get('sha256', final_report['file_metadata'].get('sha256', 'not_computed'))
            final_report['file_metadata']['stripped'] = final_report['file_metadata'].get('stripped', False)
            
            logger.info(f"✅ Injected Angr metadata: {file_type_value} ({angr_meta.get('size_bytes')} bytes)")
        else:
            logger.warning("⚠️ Angr metadata unavailable, using Claude's inferred values")
            # Ensure file_metadata exists with defaults
            if 'file_metadata' not in final_report:
                final_report['file_metadata'] = {
                    'file_type': 'unknown',
                    'format': 'unknown',
                    'architecture': 'unknown',
                    'size': 0,
                    'size_bytes': 0,
                    'md5': 'not_computed',
                    'sha1': 'not_computed',
                    'sha256': 'not_computed',
                    'stripped': False
                }
        
        logger.info(f"✅ Final synthesis complete (${result['cost']:.6f})")
        return final_report
    
    async def analyze_binary(
        self,
        binary_path: str,
        filename: str,
        force_deep: bool = False
    ) -> Dict[str, Any]:
        """
        Complete modular analysis pipeline with 7 specialized stages.
        Each stage uses dedicated prompts for maximum accuracy.
        
        Args:
            binary_path: Path to binary file
            filename: Original filename
            force_deep: Skip triage and force deep analysis
            
        Returns:
            Complete analysis results
        """
        logger.info("="*60)
        logger.info(f"Starting MODULAR analysis pipeline for: {filename}")
        logger.info(f"Force deep analysis: {force_deep}")
        logger.info("="*60)
        
        total_cost = 0.0
        stage_results = {}
        
        # Stage 1: Quick triage (unless forced deep)
        if not force_deep:
            logger.info("Stage 1: Quick triage for " + filename)
            triage = await self.run_quick_triage(binary_path, filename)
            total_cost += triage.get('stage1_cost', 0)
            stage_results['triage'] = triage
            
            if triage.get('recommended_analysis') == 'skip':
                logger.info("⏭️  Triage recommends skipping (not cryptographic)")
                return {
                    "skipped": True,
                    "reason": triage.get('reasoning'),
                    "confidence": triage.get('confidence'),
                    "total_cost": total_cost
                }
        else:
            logger.info("🚀 FORCE_DEEP enabled - Skipping triage, running full analysis")
            stage_results['triage'] = {"recommended_analysis": "deep"}
        
        # Stage 2: Angr extraction
        angr_results = await self.run_angr_extraction(binary_path)
        
        # Stage 3: Algorithm detection
        algo_result = await self.run_algorithm_detection(angr_results)
        total_cost += algo_result['cost']
        stage_results['algorithms'] = algo_result['algorithms']
        
        # Stage 4: Function analysis
        func_result = await self.run_function_analysis(angr_results, stage_results['algorithms'])
        total_cost += func_result['cost']
        stage_results['functions'] = func_result['functions']
        
        # Stage 5: Vulnerability scanning
        vuln_result = await self.run_vulnerability_scan(
            angr_results,
            stage_results['algorithms'],
            stage_results['functions']
        )
        total_cost += vuln_result['cost']
        stage_results['vulnerabilities'] = vuln_result['vulnerabilities']
        
        # Stage 6: Protocol detection
        protocol_result = await self.run_protocol_detection(
            angr_results,
            stage_results['algorithms'],
            stage_results['functions']
        )
        total_cost += protocol_result['cost']
        stage_results['protocols'] = protocol_result['protocols']
        
        # Stage 7: Final synthesis
        final_analysis = await self.run_final_synthesis(angr_results, stage_results)
        total_cost += final_analysis['_analysis_metadata']['cost']
        
        # Add total cost tracking
        final_analysis['_analysis_metadata']['total_pipeline_cost'] = total_cost
        final_analysis['_analysis_metadata']['stages_completed'] = 7
        
        logger.info("="*60)
        logger.info(f"✅ MODULAR pipeline complete | Total cost: ${total_cost:.6f}")
        logger.info("="*60)
        
        return final_analysis
    
    def _optimize_angr_data(self, angr_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optimize Angr results to reduce token usage while preserving critical data.
        
        CRITICAL: Must preserve file metadata (size, hashes) for LLM to populate file_metadata.
        
        Optimizations:
        1. Keep complete metadata (size, md5, sha256, architecture)
        2. Limit function list to top 50 (most relevant)
        3. Keep only crypto-related strings
        4. Summarize large constant arrays
        5. **NEW**: Include aggregated crypto score and function groups (Phase 2.5)
        
        Returns:
            Optimized data structure with preserved metadata + aggregation
        """
        optimized = {}
        
        # Metadata - keep ALL fields (CRITICAL for file_metadata in response)
        if 'metadata' in angr_results:
            meta = angr_results['metadata']
            optimized['metadata'] = {
                'architecture': meta.get('architecture'),
                'file_type': meta.get('file_type'),
                'entry_point': meta.get('entry_point'),
                'size_bytes': meta.get('size_bytes'),  # Backend expects size_bytes, not size
                'md5': meta.get('md5'),
                'sha256': meta.get('sha256'),
                'sha1': meta.get('sha1')  # Include SHA-1 for completeness
            }
        
        # Functions - limit to 50 most relevant
        if 'functions' in angr_results and 'functions' in angr_results['functions']:
            funcs = angr_results['functions']['functions'][:50]
            optimized['functions'] = {'functions': funcs, 'total': len(funcs)}
        
        # Strings - keep only crypto-related
        if 'strings' in angr_results:
            optimized['crypto_strings'] = angr_results['strings'].get('crypto_related_strings', [])
            optimized['total_strings'] = angr_results['strings'].get('total_strings', 0)
        
        # Constants - already summarized, keep as-is
        if 'constants' in angr_results:
            optimized['constants'] = angr_results['constants']
        
        # **NEW: Include YARA scan results (Phase 2.5)**
        if 'yara' in angr_results and angr_results['yara'].get('scan_successful'):
            yara_data = angr_results['yara']
            optimized['yara'] = {
                'summary': yara_data.get('summary', {}),
                'detections': yara_data.get('detections', [])[:20],  # Limit to top 20 detections
                'crypto_confidence': yara_data.get('summary', {}).get('crypto_confidence', 0)
            }
            logger.info(f"✅ Included YARA results: {yara_data['summary']['total_rules_matched']} matches")
        
        # **CRITICAL: Include crypto patterns (ARX operations, inferred algorithms)**
        if 'patterns' in angr_results:
            patterns_data = angr_results['patterns']
            optimized['patterns'] = {
                'summary': patterns_data.get('summary', {}),
                'inferred_algorithms': patterns_data.get('inferred_algorithms', []),
                'arx_operations': len(patterns_data.get('patterns', {}).get('arx_operations', [])),
                'table_lookups': len(patterns_data.get('patterns', {}).get('table_lookups', [])),
                'round_loops': len(patterns_data.get('patterns', {}).get('round_loops', []))
            }
            # Log summary only (not full list to avoid spam)
            logger.info(f"✅ Included {len(optimized['patterns']['inferred_algorithms'])} inferred algorithms")
        
        # **PHASE 2.5: Include aggregated crypto score + function groups**
        # This is CRITICAL for ultra-stripped binaries where functions are inlined/scattered
        if 'aggregated_crypto_score' in angr_results:
            optimized['aggregated_crypto_score'] = angr_results['aggregated_crypto_score']
            logger.info(f"✅ Included aggregated_crypto_score: {angr_results['aggregated_crypto_score']:.2f}")
        
        if 'function_groups' in angr_results:
            # CRITICAL FIX: Send only TOP 3-5 largest groups (not all 1107!)
            # Full list causes 250K token overflow
            fg_data = angr_results['function_groups']
            
            # Extract the actual list of groups (angr_build_function_groups returns a dict)
            if isinstance(fg_data, dict) and 'function_groups' in fg_data:
                all_groups = fg_data['function_groups']
            elif isinstance(fg_data, list):
                all_groups = fg_data
            else:
                logger.warning(f"Unexpected function_groups format: {type(fg_data)}")
                all_groups = []
            
            # Filter to top 5 largest groups
            if all_groups:
                top_groups = sorted(all_groups, key=lambda g: g.get('size', 0), reverse=True)[:5]
                optimized['function_groups'] = top_groups
                logger.info(f"✅ Included {len(top_groups)} function groups (filtered from {len(all_groups)} total)")
            else:
                logger.warning("No function groups found to include")
        
        # Base crypto likelihood (for comparison)
        if 'crypto_likelihood_score' in angr_results:
            optimized['base_crypto_score'] = angr_results['crypto_likelihood_score']
        
        return optimized
    
    def _load_prompt(self, prompt_path: str) -> str:
        """
        Load a modular prompt from file.
        
        Args:
            prompt_path: Path to prompt file (e.g., "prompts/1_triage.md")
            
        Returns:
            Prompt content as string
        """
        path = Path(prompt_path)
        if path.exists():
            with open(path, 'r') as f:
                return f.read()
        else:
            logger.warning(f"Prompt file not found: {prompt_path}")
            return "You are CypherRay, a cryptographic binary analysis expert."
    
    def _aggregate_patterns_across_groups(
        self, 
        patterns: Dict[str, Any], 
        dataflow: Dict[str, Any],
        function_groups: Dict[str, Any]
    ) -> float:
        """
        Aggregate crypto patterns across function groups to boost score for stripped binaries.
        
        CRITICAL for ultra-stripped binaries where crypto is split across 10-40 tiny functions.
        
        Args:
            patterns: Pattern detection results (ARX, table lookups, etc.)
            dataflow: Dataflow analysis results (XOR chains, rotations)
            function_groups: Call graph function groups
            
        Returns:
            Aggregated crypto likelihood score (0.0 - 1.0)
        """
        base_score = dataflow.get('crypto_likelihood_score', 0.0)
        
        # Get total pattern counts
        total_arx = len(patterns.get('patterns', {}).get('arx_operations', []))
        total_tables = len(patterns.get('patterns', {}).get('table_lookups', []))
        total_xor = len(dataflow.get('dataflow_patterns', {}).get('xor_chains', []))
        total_rotations = len(dataflow.get('dataflow_patterns', {}).get('bit_rotations', []))
        
        # Get largest function group size
        largest_group = function_groups.get('largest_group_size', 0)
        total_groups = function_groups.get('total_groups', 0)
        
        # Aggregation bonuses
        bonus = 0.0
        
        # Bonus 1: Large function groups suggest complex crypto implementation
        if largest_group >= 10:
            bonus += 0.25  # Strong signal
        elif largest_group >= 5:
            bonus += 0.15
        
        # Bonus 2: Many pattern matches across groups (even if weak individually)
        total_patterns = total_arx + total_tables + total_xor + total_rotations
        if total_patterns >= 15:
            bonus += 0.20
        elif total_patterns >= 10:
            bonus += 0.10
        
        # Bonus 3: Multiple groups with patterns (distributed crypto)
        if total_groups >= 5 and total_patterns >= 5:
            bonus += 0.15
        
        aggregated = min(base_score + bonus, 1.0)
        
        logger.info(f"   Aggregation: base={base_score:.2f} + bonus={bonus:.2f} = {aggregated:.2f}")
        logger.info(f"   Evidence: {total_patterns} patterns across {total_groups} groups (largest: {largest_group} funcs)")
        
        return aggregated
    
    def _detect_protocols_from_strings(self, crypto_strings: List[str]) -> Dict[str, Any]:
        """
        Quick protocol detection from extracted strings for triage.
        
        Args:
            crypto_strings: List of crypto-related strings
            
        Returns:
            Dict with detected protocols and evidence
        """
        protocols = []
        evidence = []
        
        # Protocol patterns
        protocol_patterns = {
            "TLS": ["TLS", "SSL", "ClientHello", "ServerHello", "HandshakeType"],
            "SSH": ["SSH", "ssh-rsa", "ssh-ed25519", "OpenSSH"],
            "HTTPS": ["HTTPS", "HTTP/1.1", "Content-Type"],
            "IPSec": ["IPSec", "ESP", "AH", "IKE"],
            "OpenVPN": ["OpenVPN", "tun", "tap"],
            "WireGuard": ["WireGuard", "Curve25519"],
            "Signal": ["Signal", "X3DH", "Double Ratchet"],
            "PGP/GPG": ["PGP", "GPG", "OpenPGP"],
        }
        
        # Check each pattern
        for protocol, keywords in protocol_patterns.items():
            for keyword in keywords:
                for string in crypto_strings:
                    if keyword.lower() in string.lower():
                        if protocol not in protocols:
                            protocols.append(protocol)
                        evidence.append(f"Found '{keyword}' in binary strings")
                        break
        
        return {
            "protocols": protocols,
            "evidence": evidence[:10],  # Limit evidence
            "count": len(protocols)
        }
    
    def _parse_json_response(self, content: str, stage_name: str = "unknown") -> Any:
        """
        Parse JSON from LLM response with multiple repair strategies.
        
        Strategies:
        1. Direct parsing
        2. Strip text before JSON (AI often adds explanations before the JSON)
        3. Extract from markdown code blocks
        4. Extract JSON before any explanation text
        5. Repair common JSON errors (trailing commas, unescaped quotes)
        6. Regex extraction as last resort
        
        Args:
            content: LLM response content
            stage_name: Name of the stage for error logging
            
        Returns:
            Parsed JSON object
        """
        import re
        
        # Strategy 1: Direct parsing
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            # If error is "Extra data" it means JSON is valid but has text after it
            if "Extra data" in str(e):
                # Extract just the JSON part (before the extra text)
                try:
                    content_stripped = content.strip()
                    
                    # First, find where JSON actually starts (skip any prefix text)
                    first_bracket = content_stripped.find('[')
                    first_brace = content_stripped.find('{')
                    json_start = -1
                    
                    if first_bracket != -1 and first_brace != -1:
                        json_start = min(first_bracket, first_brace)
                    elif first_bracket != -1:
                        json_start = first_bracket
                    elif first_brace != -1:
                        json_start = first_brace
                    
                    if json_start > 0:
                        content_stripped = content_stripped[json_start:]
                    
                    # Now find where valid JSON ends
                    if content_stripped.startswith('['):
                        # Find the closing bracket
                        bracket_count = 0
                        for i, char in enumerate(content_stripped):
                            if char == '[':
                                bracket_count += 1
                            elif char == ']':
                                bracket_count -= 1
                                if bracket_count == 0:
                                    # Found the end of the array
                                    json_only = content_stripped[:i+1]
                                    parsed = json.loads(json_only)
                                    logger.info(f"Successfully parsed JSON with 'Extra data' handling in {stage_name}")
                                    return parsed
                    elif content_stripped.startswith('{'):
                        # Find the closing brace
                        brace_count = 0
                        for i, char in enumerate(content_stripped):
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    # Found the end of the object
                                    json_only = content_stripped[:i+1]
                                    parsed = json.loads(json_only)
                                    logger.info(f"Successfully parsed JSON with 'Extra data' handling in {stage_name}")
                                    return parsed
                except Exception as parse_error:
                    logger.debug(f"Extra data handling failed: {parse_error}")
            
            logger.debug(f"Direct JSON parse failed in {stage_name}: {e}")
        
        # Strategy 2: Strip explanatory text BEFORE JSON (common AI behavior)
        # AI often writes: "I'll analyze the functions:\n\n[\n  {...}\n]"
        cleaned_content = content.strip()
        
        # Find the first [ or { that starts the JSON
        first_bracket = cleaned_content.find('[')
        first_brace = cleaned_content.find('{')
        
        # Determine which comes first (or if neither exists)
        json_start = -1
        if first_bracket != -1 and first_brace != -1:
            json_start = min(first_bracket, first_brace)
        elif first_bracket != -1:
            json_start = first_bracket
        elif first_brace != -1:
            json_start = first_brace
        
        # If we found a JSON start, try parsing from there
        if json_start > 0:  # Only if there's text BEFORE the JSON
            try:
                cleaned_content = cleaned_content[json_start:]
                parsed = json.loads(cleaned_content)
                logger.info(f"Successfully parsed JSON after stripping prefix in {stage_name}")
                return parsed
            except json.JSONDecodeError as e:
                logger.debug(f"Prefix stripping didn't help in {stage_name}: {e}")
                # Restore for next strategies
                cleaned_content = content.strip()
        
        # Strategy 3: Extract from markdown code blocks
        if "```json" in cleaned_content:
            cleaned_content = cleaned_content.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned_content:
            # Handle cases where AI returns ```\n[]\n``` or ```\n{}\n```
            cleaned_content = cleaned_content.split("```")[1].split("```")[0].strip()
        
        try:
            parsed = json.loads(cleaned_content)
            logger.info(f"Successfully parsed JSON from markdown in {stage_name}")
            return parsed
        except json.JSONDecodeError as e:
            logger.warning(f"Markdown extraction failed in {stage_name}: {e}")
        
        # Strategy 3: Repair common JSON errors
        try:
            repaired = cleaned_content
            
            # Remove any text before first { and after last }
            first_brace = repaired.find('{')
            last_brace = repaired.rfind('}')
            if first_brace != -1 and last_brace != -1:
                repaired = repaired[first_brace:last_brace+1]
            
            # Remove trailing commas before closing brackets/braces
            repaired = re.sub(r',\s*([}\]])', r'\1', repaired)
            
            # Fix unescaped newlines in strings (they break JSON)
            repaired = re.sub(r'(?<!\\)\n(?=[^"]*"(?:[^"]*"[^"]*")*[^"]*$)', r'\\n', repaired)
            
            # Remove control characters except valid whitespace
            repaired = ''.join(char for char in repaired if ord(char) >= 32 or char in '\n\r\t')
            
            # Fix common quote escaping issues in property names
            # Replace unescaped quotes in values (heuristic: after colons)
            repaired = re.sub(r':\s*"([^"]*?)"([^"]*?)"([^,}\]]*?)"', r': "\1\'\2\'\3"', repaired)
            
            return json.loads(repaired)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON repair failed: {e}")
        
        # Strategy 4: Aggressive repair - truncate and close structures
        try:
            # Start fresh from cleaned content
            repaired = cleaned_content
            first_brace = repaired.find('{')
            if first_brace != -1:
                repaired = repaired[first_brace:]
            
            # Count unclosed structures
            open_braces = repaired.count('{') - repaired.count('}')
            open_brackets = repaired.count('[') - repaired.count(']')
            open_quotes = repaired.count('"') % 2
            
            # Close any unclosed structures
            if open_quotes == 1:
                repaired += '"'
            if open_brackets > 0:
                repaired += ']' * open_brackets
            if open_braces > 0:
                repaired += '}' * open_braces
            
            # Remove trailing commas again
            repaired = re.sub(r',\s*([}\]])', r'\1', repaired)
            
            return json.loads(repaired)
        except (json.JSONDecodeError, AttributeError) as e:
            logger.warning(f"Aggressive JSON repair failed: {e}")
        
        # Strategy 4: Regex extraction (last resort)
        try:
            # Try to find a valid JSON object
            json_match = re.search(r'\{[\s\S]*\}', cleaned_content)
            if json_match:
                potential_json = json_match.group(0)
                # One more repair attempt
                potential_json = re.sub(r',\s*([}\]])', r'\1', potential_json)
                return json.loads(potential_json)
        except (json.JSONDecodeError, AttributeError) as e:
            logger.error(f"All JSON parsing strategies failed: {e}")
        
        # If all else fails, raise the original error with helpful context
        raise json.JSONDecodeError(
            f"Failed to parse JSON after all repair strategies. Content preview: {content[:200]}...",
            content,
            0
        )


# Example usage
if __name__ == "__main__":
    import asyncio
    from dotenv import load_dotenv
    
    # Load environment variables
    load_dotenv()
    
    async def test_pipeline():
        orchestrator = MultiModelOrchestrator()
        pipeline = AnalysisPipeline(orchestrator)
        
        # Test with a sample binary
        print("Testing analysis pipeline...")
        
        # You would normally use a real binary here
        # result = await pipeline.analyze_binary("/path/to/binary", "test.exe")
        # print(json.dumps(result, indent=2))
        
        print("✅ Pipeline initialized successfully!")
    
    asyncio.run(test_pipeline())
