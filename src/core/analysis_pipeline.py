"""
Orchestrator-based Analysis Pipeline
Intelligent multi-stage analysis using cost-optimized model selection.
"""

import json
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
        
        # Detect constants
        try:
            results['constants'] = angr_detect_crypto_constants(binary_path)
            logger.info(f"✅ Found {len(results['constants'].get('detected_constants', []))} crypto constants")
        except Exception as e:
            logger.error(f"Constant detection failed: {e}")
            results['constants'] = {}
        
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
        
        query = f"""
{vuln_prompt}

=== INPUT DATA ===

Detected Algorithms: {json.dumps(detected_algorithms, indent=2)}

Detected Functions: {json.dumps(detected_functions, indent=2)}

Strings: {json.dumps(optimized.get('crypto_strings', []))}

Constants: {json.dumps(optimized.get('constants', {}))}

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
        
        final_report = self._parse_json_response(result['content'])
        
        # Add analysis metadata
        final_report['_analysis_metadata'] = {
            'model_used': result['model'],
            'provider': result['provider'],
            'cost': result['cost'],
            'duration': result['duration']
        }
        
        logger.info(f"✅ Final synthesis complete using {result['model']} (${result['cost']:.6f})")
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
        logger.info("="*60)
        
        total_cost = 0.0
        stage_results = {}
        
        # Stage 1: Quick triage (unless forced deep)
        if not force_deep:
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
        
        Returns:
            Optimized data structure with preserved metadata
        """
        optimized = {}
        
        # Metadata - keep ALL fields (CRITICAL for file_metadata in response)
        if 'metadata' in angr_results:
            meta = angr_results['metadata']
            optimized['metadata'] = {
                'architecture': meta.get('architecture'),
                'file_type': meta.get('file_type'),
                'entry_point': meta.get('entry_point'),
                'size': meta.get('size'),
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
    
    def _parse_json_response(self, content: str) -> Any:
        """
        Parse JSON from LLM response, handling markdown code blocks.
        
        Args:
            content: LLM response content
            
        Returns:
            Parsed JSON object
        """
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try extracting from code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            return json.loads(content)


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
