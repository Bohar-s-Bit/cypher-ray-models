"""
OpenAI API client wrapper with error handling, retry logic, and cost tracking.
"""

import time
import json
from typing import Dict, List, Optional, Any
from openai import OpenAI, OpenAIError, RateLimitError, APITimeoutError
import os
from src.utils.logger import get_logger
from src.utils.cost_tracker import CostTracker

logger = get_logger(__name__)


class OpenAIClient:
    """Wrapper for OpenAI API with enhanced error handling and tracking."""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        cost_tracker: Optional[CostTracker] = None,
        model_config: Optional[Dict] = None
    ):
        """
        Initialize OpenAI client.
        
        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            cost_tracker: CostTracker instance for logging costs
            model_config: Model configuration dict
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key not provided")
        
        # Initialize client with just API key (no custom httpx config to avoid version conflicts)
        self.client = OpenAI(api_key=self.api_key)
        self.cost_tracker = cost_tracker
        self.model_config = model_config or {}
        
        logger.info("OpenAI client initialized")
    
    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4o",
        temperature: float = 0.2,
        max_tokens: int = 4000,
        tools: Optional[List[Dict]] = None,
        tool_choice: str = "auto",
        max_retries: int = 3,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a chat completion with retry logic.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model name
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            tools: Function calling tools
            tool_choice: Tool choice strategy
            max_retries: Maximum retry attempts
            **kwargs: Additional parameters
            
        Returns:
            Response dict with 'message', 'usage', 'cost', etc.
        """
        start_time = time.time()
        last_error = None
        
        for attempt in range(max_retries):
            try:
                logger.debug(f"OpenAI API call attempt {attempt + 1}/{max_retries} | Model: {model}")
                
                # Make API call
                response = self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools if tools else None,
                    tool_choice=tool_choice if tools else None,
                    **kwargs
                )
                
                # Calculate duration
                duration = time.time() - start_time
                
                # Extract usage and calculate cost
                usage = response.usage
                input_tokens = usage.prompt_tokens
                output_tokens = usage.completion_tokens
                
                cost = self._calculate_cost(model, input_tokens, output_tokens)
                
                # Track cost
                if self.cost_tracker:
                    self.cost_tracker.record_call(
                        model=model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        duration_seconds=duration,
                        success=True
                    )
                
                logger.info(
                    f"OpenAI call successful | Model: {model} | "
                    f"Tokens: {input_tokens}+{output_tokens} | "
                    f"Cost: ${cost:.6f} | Duration: {duration:.2f}s"
                )
                
                # Return structured response
                return {
                    'message': response.choices[0].message,
                    'usage': {
                        'input_tokens': input_tokens,
                        'output_tokens': output_tokens,
                        'total_tokens': input_tokens + output_tokens
                    },
                    'cost': cost,
                    'duration': duration,
                    'model': model,
                    'finish_reason': response.choices[0].finish_reason
                }
                
            except RateLimitError as e:
                last_error = e
                wait_time = (2 ** attempt) * 2  # Exponential backoff: 2, 4, 8 seconds
                logger.warning(f"Rate limit hit. Waiting {wait_time}s before retry {attempt + 1}/{max_retries}")
                time.sleep(wait_time)
                
            except APITimeoutError as e:
                last_error = e
                logger.warning(f"API timeout on attempt {attempt + 1}/{max_retries}")
                time.sleep(2 ** attempt)
                
            except OpenAIError as e:
                last_error = e
                logger.error(f"OpenAI API error: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    break
                    
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error: {str(e)}", exc_info=True)
                break
        
        # All retries failed
        duration = time.time() - start_time
        if self.cost_tracker:
            self.cost_tracker.record_call(
                model=model,
                input_tokens=0,
                output_tokens=0,
                duration_seconds=duration,
                success=False,
                error_message=str(last_error)
            )
        
        raise Exception(f"OpenAI API call failed after {max_retries} retries: {str(last_error)}")
    
    def create_embedding(
        self,
        text: str,
        model: str = "text-embedding-3-large",
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """
        Create text embedding.
        
        Args:
            text: Text to embed
            model: Embedding model name
            max_retries: Maximum retry attempts
            
        Returns:
            Dict with 'embedding' vector and metadata
        """
        start_time = time.time()
        last_error = None
        
        for attempt in range(max_retries):
            try:
                response = self.client.embeddings.create(
                    model=model,
                    input=text
                )
                
                duration = time.time() - start_time
                tokens = response.usage.total_tokens
                cost = self._calculate_embedding_cost(model, tokens)
                
                if self.cost_tracker:
                    self.cost_tracker.record_call(
                        model=model,
                        input_tokens=tokens,
                        output_tokens=0,
                        duration_seconds=duration,
                        success=True
                    )
                
                return {
                    'embedding': response.data[0].embedding,
                    'tokens': tokens,
                    'cost': cost,
                    'duration': duration,
                    'model': model
                }
                
            except (RateLimitError, APITimeoutError) as e:
                last_error = e
                time.sleep(2 ** attempt)
                
            except Exception as e:
                last_error = e
                logger.error(f"Embedding error: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    break
        
        raise Exception(f"Embedding creation failed: {str(last_error)}")
    
    def _calculate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for chat completion."""
        # Load pricing from config
        config_path = "config/model_config.json"
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            for model_info in config['models'].values():
                if model_info['model'] == model:
                    input_cost = (input_tokens / 1000) * model_info.get('cost_per_1k_input_tokens', 0)
                    output_cost = (output_tokens / 1000) * model_info.get('cost_per_1k_output_tokens', 0)
                    return input_cost + output_cost
        except:
            pass
        
        return 0.0
    
    def _calculate_embedding_cost(self, model: str, tokens: int) -> float:
        """Calculate cost for embeddings."""
        try:
            with open("config/model_config.json", 'r') as f:
                config = json.load(f)
            
            for model_info in config['models'].values():
                if model_info['model'] == model:
                    return (tokens / 1000) * model_info.get('cost_per_1k_tokens', 0)
        except:
            pass
        
        return 0.0


# Example usage
if __name__ == "__main__":
    from src.utils.cost_tracker import CostTracker
    
    tracker = CostTracker()
    client = OpenAIClient(cost_tracker=tracker)
    
    # Test chat completion
    print("\n🤖 Testing chat completion...")
    response = client.chat_completion(
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is 2+2?"}
        ],
        model="gpt-4o-mini",
        max_tokens=100
    )
    
    print(f"Response: {response['message'].content}")
    print(f"Cost: ${response['cost']:.6f}")
    
    # Test embeddings
    print("\n🔢 Testing embeddings...")
    embedding = client.create_embedding("Hello, world!")
    print(f"Embedding dimensions: {len(embedding['embedding'])}")
    print(f"Cost: ${embedding['cost']:.6f}")
    
    # Print cost report
    print("\n" + tracker.export_report(format='text'))
    
    print("\n✅ OpenAI client test complete!")
