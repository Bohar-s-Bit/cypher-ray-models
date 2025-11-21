"""
Anthropic API client wrapper with error handling, retry logic, and cost tracking.
"""

import time
import json
from typing import Dict, List, Optional, Any
import anthropic
from anthropic import Anthropic, APIError, RateLimitError, APITimeoutError
import os
from src.utils.logger import get_logger
from src.utils.cost_tracker import CostTracker

logger = get_logger(__name__)


class AnthropicClient:
    """Wrapper for Anthropic API with enhanced error handling and tracking."""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        cost_tracker: Optional[CostTracker] = None,
        model_config: Optional[Dict] = None
    ):
        """
        Initialize Anthropic client.
        
        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            cost_tracker: CostTracker instance for logging costs
            model_config: Model configuration dict
        """
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY') or os.getenv('ANTRHOPIC_API_KEY')
        if not self.api_key:
            raise ValueError("Anthropic API key not provided")
        
        self.client = Anthropic(api_key=self.api_key)
        self.cost_tracker = cost_tracker
        self.model_config = model_config or {}
        
        logger.info("Anthropic client initialized")
    
    def create_message(
        self,
        messages: List[Dict[str, str]],
        model: str = "claude-3-5-sonnet-20241022",
        system: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 8000,
        max_retries: int = 3,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a message with Claude with retry logic.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model name
            system: System prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            max_retries: Maximum retry attempts
            **kwargs: Additional parameters
            
        Returns:
            Response dict with 'content', 'usage', 'cost', etc.
        """
        start_time = time.time()
        last_error = None
        
        for attempt in range(max_retries):
            try:
                logger.debug(f"Anthropic API call attempt {attempt + 1}/{max_retries} | Model: {model}")
                
                # Make API call
                response = self.client.messages.create(
                    model=model,
                    messages=messages,
                    system=system if system else anthropic.NOT_GIVEN,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs
                )
                
                # Calculate duration
                duration = time.time() - start_time
                
                # Extract usage and calculate cost
                input_tokens = response.usage.input_tokens
                output_tokens = response.usage.output_tokens
                
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
                    f"Anthropic call successful | Model: {model} | "
                    f"Tokens: {input_tokens}+{output_tokens} | "
                    f"Cost: ${cost:.6f} | Duration: {duration:.2f}s"
                )
                
                # Extract text content
                content_text = ""
                if response.content:
                    for block in response.content:
                        if hasattr(block, 'text'):
                            content_text += block.text
                
                # Return structured response
                return {
                    'content': content_text,
                    'raw_response': response,
                    'usage': {
                        'input_tokens': input_tokens,
                        'output_tokens': output_tokens,
                        'total_tokens': input_tokens + output_tokens
                    },
                    'cost': cost,
                    'duration': duration,
                    'model': model,
                    'stop_reason': response.stop_reason
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
                
            except APIError as e:
                last_error = e
                logger.error(f"Anthropic API error: {str(e)}")
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
        
        raise Exception(f"Anthropic API call failed after {max_retries} retries: {str(last_error)}")
    
    def create_message_stream(
        self,
        messages: List[Dict[str, str]],
        model: str = "claude-3-5-sonnet-20241022",
        system: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 8000,
        **kwargs
    ):
        """
        Create a streaming message with Claude.
        
        Args:
            messages: List of message dicts
            model: Model name
            system: System prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            **kwargs: Additional parameters
            
        Yields:
            Content chunks as they arrive
        """
        try:
            with self.client.messages.stream(
                model=model,
                messages=messages,
                system=system if system else anthropic.NOT_GIVEN,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs
            ) as stream:
                for text in stream.text_stream:
                    yield text
                    
        except Exception as e:
            logger.error(f"Streaming error: {str(e)}")
            raise
    
    def _calculate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for message creation."""
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


# Example usage
if __name__ == "__main__":
    from src.utils.cost_tracker import CostTracker
    
    tracker = CostTracker()
    client = AnthropicClient(cost_tracker=tracker)
    
    # Test message creation
    print("\n🤖 Testing Claude message creation...")
    response = client.create_message(
        messages=[
            {"role": "user", "content": "What is 2+2? Answer briefly."}
        ],
        model="claude-3-5-sonnet-20241022",
        max_tokens=100
    )
    
    print(f"Response: {response['content']}")
    print(f"Cost: ${response['cost']:.6f}")
    
    # Test streaming
    print("\n📡 Testing streaming...")
    print("Stream: ", end="", flush=True)
    for chunk in client.create_message_stream(
        messages=[
            {"role": "user", "content": "Count from 1 to 5."}
        ],
        max_tokens=100
    ):
        print(chunk, end="", flush=True)
    print()
    
    # Print cost report
    print("\n" + tracker.export_report(format='text'))
    
    print("\n✅ Anthropic client test complete!")
