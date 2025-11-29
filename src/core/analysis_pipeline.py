"""
Orchestrator-based Analysis Pipeline
Intelligent multi-stage analysis using cost-optimized model selection.
"""

import json
import time
import tempfile
import os
from typing import Dict, Any, List
from pathlib import Path

from src.models.multi_model_orchestrator import MultiModelOrchestrator
from src.core.angr_tools import check_angr_available
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
        
    async def run_quick_triage(self, binary_path: str, filename: str) -> Dict[str, Any]:
        """
        Stage 1: Quick triage using specialized modular prompt.
        Determines if binary is worth deep analysis.
        
        Returns:
            Dict with is_crypto_likely, confidence, reasoning
        """
        logger.info(f"Stage 1: Quick triage for {filename}")
        
        # Load specialized triage prompt
        triage_prompt = self._load_prompt("prompts/1_triage.md")
        
        # Gather minimal context
        context = {"filename": filename, "size": os.path.getsize(binary_path)}
        
        if self.angr_available:
            from src.tools.angr_metadata import angr_analyze_binary_metadata
            from src.tools.angr_strings import angr_analyze_strings
            
            metadata = angr_analyze_binary_metadata(binary_path)
            strings = angr_analyze_strings(binary_path)
            
            context.update({
                "architecture": metadata.get("architecture"),
                "crypto_strings": strings.get("crypto_related_strings", [])[:10]
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
        triage = self._parse_json_response(result['content'])
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
            logger.info("✅ Metadata extracted")
        except Exception as e:
            logger.error(f"Metadata extraction failed: {e}")
            results['metadata'] = {}
        
        # Extract functions
        try:
            results['functions'] = angr_extract_functions(binary_path, limit=100)
            logger.info(f"✅ Extracted {len(results['functions'].get('functions', []))} functions")
        except Exception as e:
            logger.error(f"Function extraction failed: {e}")
            results['functions'] = {}
        
        # Analyze strings
        try:
            results['strings'] = angr_analyze_strings(binary_path)
            logger.info(f"✅ Found {len(results['strings'].get('crypto_related_strings', []))} crypto strings")
        except Exception as e:
            logger.error(f"String analysis failed: {e}")
            results['strings'] = {}
        
        # Detect constants (ENHANCED)
        try:
            results['constants'] = angr_detect_crypto_constants(binary_path)
            const_count = len(results['constants'].get('detected_constants', []))
            logger.info(f"✅ Found {const_count} crypto constants")
            if results['constants'].get('algorithm_groups'):
                logger.info(f"   Algorithm hints: {list(results['constants']['algorithm_groups'].keys())}")
        except Exception as e:
            logger.error(f"Constant detection failed: {e}")
            results['constants'] = {}
        
        # Detect crypto patterns (NEW)
        try:
            logger.info("Starting crypto pattern detection...")
            results['patterns'] = angr_detect_crypto_patterns(binary_path)
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
            results['patterns'] = {"error": str(e)}
        
        # Analyze data flow (NEW)
        try:
            logger.info("Starting dataflow analysis...")
            results['dataflow'] = angr_analyze_dataflow(binary_path)
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
            results['dataflow'] = {"error": str(e)}
        
        # Build function groups for cross-function aggregation (NEW for stripped binaries)
        try:
            logger.info("Building function call graph for aggregation...")
            from src.tools.angr_patterns import angr_build_function_groups
            results['function_groups'] = angr_build_function_groups(binary_path)
            group_count = results['function_groups'].get('total_groups', 0)
            largest_group = results['function_groups'].get('largest_group_size', 0)
            logger.info(f"✅ Found {group_count} function groups (largest: {largest_group} functions)")
            
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
        
        algorithms = self._parse_json_response(result['content'])
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
        
        Returns:
            Dict with function analysis results
        """
        logger.info("Stage 4: Function analysis")
        
        # Load specialized function analysis prompt
        func_prompt = self._load_prompt("prompts/3_function_analysis.md")
        
        optimized = self._optimize_angr_data(angr_results)
        
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
        
        functions = self._parse_json_response(result['content'])
        logger.info(f"✅ Analyzed {len(functions) if isinstance(functions, list) else 0} functions")
        
        return {
            'functions': functions,
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
        
        vulnerabilities = self._parse_json_response(result['content'])
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
        
        protocols = self._parse_json_response(result['content'])
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
            final_report = self._parse_json_response(result['content'])
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
            
            # Re-raise with more context
            raise ValueError(f"Final synthesis JSON parsing failed at position {e.pos}: {e.msg}") from e
        
        # Add analysis metadata
        final_report['_analysis_metadata'] = {
            'model_used': 'cypherray-ai-engine',
            'provider': 'cypherray',
            'cost': result['cost'],
            'duration': result['duration']
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
            optimized['function_groups'] = angr_results['function_groups']
            logger.info(f"✅ Included {len(angr_results['function_groups'])} function groups")
        
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
    
    def _parse_json_response(self, content: str) -> Any:
        """
        Parse JSON from LLM response with multiple repair strategies.
        
        Strategies:
        1. Direct parsing
        2. Extract from markdown code blocks
        3. Repair common JSON errors (trailing commas, unescaped quotes)
        4. Regex extraction as last resort
        
        Args:
            content: LLM response content
            
        Returns:
            Parsed JSON object
        """
        import re
        
        # Strategy 1: Direct parsing
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning(f"Direct JSON parse failed: {e}")
        
        # Strategy 2: Extract from markdown code blocks
        cleaned_content = content
        if "```json" in content:
            cleaned_content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            cleaned_content = content.split("```")[1].split("```")[0].strip()
        
        try:
            return json.loads(cleaned_content)
        except json.JSONDecodeError as e:
            logger.warning(f"Markdown extraction failed: {e}")
        
        # Strategy 3: Repair common JSON errors
        try:
            repaired = cleaned_content
            
            # Remove trailing commas before closing brackets/braces
            repaired = re.sub(r',\s*([}\]])', r'\1', repaired)
            
            # Fix common quote escaping issues in property names
            # Replace unescaped quotes in values (heuristic: after colons)
            repaired = re.sub(r':\s*"([^"]*?)"([^"]*?)"([^,}\]]*?)"', r': "\1\'\2\'\3"', repaired)
            
            return json.loads(repaired)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON repair failed: {e}")
        
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
