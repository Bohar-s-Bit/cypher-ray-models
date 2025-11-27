"""
Multi-Model Orchestrator - Intelligently selects and coordinates multiple LLM models.
Implements cost optimization, caching, and fallback strategies.
"""

import json
import hashlib
import asyncio
from typing import Dict, Any, Optional, List
from pathlib import Path

from src.models.openai_client import OpenAIClient
from src.models.anthropic_client import AnthropicClient
from src.utils.logger import get_logger
from src.utils.cost_tracker import CostTracker
from src.utils.cache_manager import CacheManager

# Analysis version - increment when detection logic changes (invalidates cache)
ANALYSIS_VERSION = "v4.1-json-safety-reduced-logs"

logger = get_logger(__name__)


class MultiModelOrchestrator:
    """Orchestrates multiple LLM models for optimal cost and performance."""
    
    def __init__(
        self,
        cost_tracker: Optional[CostTracker] = None,
        enable_caching: bool = True,
        config_path: str = "config/model_config.json"
    ):
        """
        Initialize the orchestrator.
        
        Args:
            cost_tracker: CostTracker instance for monitoring costs
            enable_caching: Whether to enable response caching
            config_path: Path to model configuration file
        """
        self.cost_tracker = cost_tracker or CostTracker(config_path)
        self.cache_manager = CacheManager() if enable_caching else None
        
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        # Initialize clients
        self.openai_client = OpenAIClient(cost_tracker=self.cost_tracker)
        self.anthropic_client = AnthropicClient(cost_tracker=self.cost_tracker)
        
        self.strategy = self.config.get('model_selection_strategy', {})
        logger.info("Multi-Model Orchestrator initialized")
    
    def _generate_cache_key(self, query: str, context: Dict, analysis_type: str) -> str:
        """Generate a unique cache key for the query."""
        combined = f"{ANALYSIS_VERSION}:{query}:{json.dumps(context, sort_keys=True)}:{analysis_type}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[Dict]:
        """Retrieve cached response if available."""
        if not self.cache_manager:
            return None
        
        cached = self.cache_manager.get(cache_key)
        if cached:
            logger.info(f"Cache HIT: {cache_key[:16]}...")
            return cached
        
        logger.debug(f"Cache MISS: {cache_key[:16]}...")
        return None
    
    def _cache_response(self, cache_key: str, response: Dict):
        """Cache a response."""
        if self.cache_manager:
            ttl = self.config.get('analysis_options', {}).get('cache_ttl_hours', 24) * 3600
            self.cache_manager.set(cache_key, response, ttl=ttl)
            logger.debug(f"Cached response: {cache_key[:16]}...")
    
    def select_model(self, analysis_type: str, retry_count: int = 0) -> Dict[str, Any]:
        """
        Select the appropriate model based on analysis type and retry count.
        
        Args:
            analysis_type: Type of analysis (quick_classify, main_analysis, long_context, reasoning)
            retry_count: Number of retries (for fallback)
            
        Returns:
            Dict with model configuration
        """
        # Get fallback order from config
        fallback_order = self.strategy.get('fallback_order', [
            'quick_classifier',
            'main_analyzer',
            'long_context_analyzer',
            'reasoning_model'
        ])
        
        # Map analysis types to model keys
        type_to_model = {
            'quick_classify': 'quick_classifier',
            'main_analysis': 'main_analyzer',
            'long_context': 'long_context_analyzer',
            'reasoning': 'reasoning_model',
            'protocol_analysis': 'reasoning_model'
        }
        
        # Get primary model for this analysis type
        primary_model_key = type_to_model.get(analysis_type, 'main_analyzer')
        
        # If using cheapest first strategy
        if self.strategy.get('use_cheapest_first', True) and retry_count == 0:
            model_key = primary_model_key
        else:
            # Use fallback based on retry count
            idx = min(retry_count, len(fallback_order) - 1)
            model_key = fallback_order[idx]
        
        model_config = self.config['models'].get(model_key, self.config['models']['main_analyzer'])
        logger.debug(f"Selected model: {model_config['model']} for {analysis_type} (retry: {retry_count})")
        
        return model_config
    
    async def analyze(
        self,
        query: str,
        context: Dict[str, Any],
        analysis_type: str = 'main_analysis',
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """
        Analyze using the orchestrator with intelligent model selection.
        
        Args:
            query: The analysis query/prompt
            context: Context data (e.g., Angr analysis results)
            analysis_type: Type of analysis to perform
            max_retries: Maximum number of retries with fallback models
            
        Returns:
            Analysis response with metadata
        """
        # Check cache
        cache_key = self._generate_cache_key(query, context, analysis_type)
        cached_response = self._get_cached_response(cache_key)
        if cached_response:
            return cached_response
        
        last_error = None
        
        for retry in range(max_retries + 1):
            try:
                # Select model
                model_config = self.select_model(analysis_type, retry)
                provider = model_config['provider']
                model_name = model_config['model']
                
                logger.info(f"Attempt {retry + 1}/{max_retries + 1}: Analyzing with AI model")
                
                # Prepare messages
                messages = [
                    {"role": "user", "content": query}
                ]
                
                # Add context if provided
                if context:
                    context_str = f"\n\nContext:\n{json.dumps(context, indent=2)}"
                    messages[0]["content"] += context_str
                
                # Call appropriate client
                if provider == 'openai':
                    response = self.openai_client.chat_completion(
                        messages=messages,
                        model=model_name,
                        temperature=model_config.get('temperature', 0.2),
                        max_tokens=model_config.get('max_tokens', 4000)
                    )
                    
                    result = {
                        'content': response['message'].content,
                        'provider': 'openai',
                        'model': model_name,
                        'usage': response['usage'],
                        'cost': response['cost'],
                        'duration': response['duration']
                    }
                    
                elif provider == 'anthropic':
                    response = self.anthropic_client.create_message(
                        messages=messages,
                        model=model_name,
                        temperature=model_config.get('temperature', 0.2),
                        max_tokens=model_config.get('max_tokens', 8000)
                    )
                    
                    result = {
                        'content': response['content'],
                        'provider': 'anthropic',
                        'model': model_name,
                        'usage': response['usage'],
                        'cost': response['cost'],
                        'duration': response['duration']
                    }
                else:
                    raise ValueError(f"Unknown provider: {provider}")
                
                # Cache successful response
                self._cache_response(cache_key, result)
                
                logger.info(f"Analysis successful")
                return result
                
            except Exception as e:
                last_error = e
                logger.warning(f"Attempt {retry + 1} failed with {model_config.get('model', 'unknown')}: {str(e)}")
                
                if retry < max_retries:
                    logger.info(f"Retrying with fallback model...")
                else:
                    logger.error(f"All retry attempts exhausted")
        
        # All retries failed
        raise Exception(f"Analysis failed after {max_retries + 1} attempts. Last error: {str(last_error)}")
    
    async def parallel_analyze(
        self,
        tasks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Run multiple analysis tasks in parallel.
        
        Args:
            tasks: List of task dicts with 'query', 'context', 'analysis_type'
            
        Returns:
            List of results in same order as tasks
        """
        max_parallel = self.config.get('analysis_options', {}).get('max_parallel_tasks', 5)
        
        # Run in batches
        results = []
        for i in range(0, len(tasks), max_parallel):
            batch = tasks[i:i + max_parallel]
            logger.info(f"Running parallel batch: {len(batch)} tasks")
            
            batch_results = await asyncio.gather(*[
                self.analyze(
                    query=task['query'],
                    context=task.get('context', {}),
                    analysis_type=task.get('analysis_type', 'main_analysis')
                )
                for task in batch
            ])
            
            results.extend(batch_results)
        
        return results
    
    def get_cost_summary(self) -> Dict[str, Any]:
        """Get cost summary from tracker."""
        return {
            'total_cost': self.cost_tracker.get_total_cost(),
            'cost_by_model': self.cost_tracker.get_cost_by_model(),
            'cost_by_provider': self.cost_tracker.get_cost_by_provider(),
            'token_usage': self.cost_tracker.get_token_usage(),
            'call_statistics': self.cost_tracker.get_call_statistics()
        }


# Example usage
if __name__ == "__main__":
    async def test_orchestrator():
        orchestrator = MultiModelOrchestrator()
        
        # Test quick classification
        print("\n🔍 Testing quick classification...")
        result = await orchestrator.analyze(
            query="Is this code cryptographic? def xor(a, b): return a ^ b",
            context={},
            analysis_type='quick_classify'
        )
        print(f"Result: {result['content'][:200]}")
        print(f"Cost: ${result['cost']:.6f}")
        
        # Test main analysis
        print("\n🔬 Testing main analysis...")
        result = await orchestrator.analyze(
            query="Analyze this function for crypto patterns",
            context={"function": "encrypt_aes", "operations": ["xor", "shift", "substitute"]},
            analysis_type='main_analysis'
        )
        print(f"Result preview: {result['content'][:200]}")
        print(f"Provider: {result['provider']}, Model: {result['model']}")
        
        # Test parallel analysis
        print("\n⚡ Testing parallel analysis...")
        tasks = [
            {"query": f"Analyze function {i}", "analysis_type": "quick_classify"}
            for i in range(3)
        ]
        results = await orchestrator.parallel_analyze(tasks)
        print(f"Completed {len(results)} parallel tasks")
        
        # Print cost summary
        print("\n💰 Cost Summary:")
        summary = orchestrator.get_cost_summary()
        print(f"Total Cost: ${summary['total_cost']:.4f}")
        print(f"By Provider: {summary['cost_by_provider']}")
    
    # Run test
    import asyncio
    asyncio.run(test_orchestrator())
    print("\n✅ Orchestrator test complete!")
