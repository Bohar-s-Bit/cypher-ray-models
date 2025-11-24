"""
Cost tracking system for LLM API calls.
Tracks token usage and calculates costs across multiple providers.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class APICall:
    """Record of a single API call."""
    timestamp: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    cost: float
    duration_seconds: float
    success: bool
    error_message: Optional[str] = None


class CostTracker:
    """Track and calculate costs for LLM API calls."""
    
    def __init__(self, model_config_path: str = "config/model_config.json"):
        """
        Initialize cost tracker.
        
        Args:
            model_config_path: Path to model configuration file with pricing
        """
        self.calls: List[APICall] = []
        self.model_costs = self._load_model_costs(model_config_path)
        self.session_start = datetime.now()
        
    def _load_model_costs(self, config_path: str) -> Dict:
        """Load model pricing from configuration."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            costs = {}
            for model_id, model_info in config.get('models', {}).items():
                costs[model_info['model']] = {
                    'provider': model_info['provider'],
                    'cost_per_1k_input': model_info.get('cost_per_1k_input_tokens', 0),
                    'cost_per_1k_output': model_info.get('cost_per_1k_output_tokens', 0)
                }
            
            return costs
        except Exception as e:
            print(f"Warning: Could not load model costs: {e}")
            return {}
    
    def record_call(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        duration_seconds: float,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> float:
        """
        Record an API call and calculate its cost.
        
        Args:
            model: Model name (e.g., 'gpt-4o', 'claude-3-5-sonnet-20241022')
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            duration_seconds: Call duration in seconds
            success: Whether the call succeeded
            error_message: Error message if call failed
            
        Returns:
            Cost of the call in USD
        """
        # Calculate cost
        cost = self._calculate_cost(model, input_tokens, output_tokens)
        
        # Get provider
        provider = self.model_costs.get(model, {}).get('provider', 'unknown')
        
        # Record call
        call = APICall(
            timestamp=datetime.now().isoformat(),
            model=model,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost,
            duration_seconds=duration_seconds,
            success=success,
            error_message=error_message
        )
        
        self.calls.append(call)
        
        return cost
    
    def _calculate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for a specific model and token count."""
        if model not in self.model_costs:
            return 0.0
        
        pricing = self.model_costs[model]
        input_cost = (input_tokens / 1000) * pricing['cost_per_1k_input']
        output_cost = (output_tokens / 1000) * pricing['cost_per_1k_output']
        
        return input_cost + output_cost
    
    def get_total_cost(self) -> float:
        """Get total cost of all API calls."""
        return sum(call.cost for call in self.calls)
    
    def get_cost_by_model(self) -> Dict[str, float]:
        """Get cost breakdown by model."""
        costs = defaultdict(float)
        for call in self.calls:
            costs[call.model] += call.cost
        return dict(costs)
    
    def get_cost_by_provider(self) -> Dict[str, float]:
        """Get cost breakdown by provider."""
        costs = defaultdict(float)
        for call in self.calls:
            costs[call.provider] += call.cost
        return dict(costs)
    
    def get_token_usage(self) -> Dict:
        """Get total token usage statistics."""
        total_input = sum(call.input_tokens for call in self.calls)
        total_output = sum(call.output_tokens for call in self.calls)
        
        return {
            'total_input_tokens': total_input,
            'total_output_tokens': total_output,
            'total_tokens': total_input + total_output,
            'by_model': self._get_tokens_by_model()
        }
    
    def _get_tokens_by_model(self) -> Dict:
        """Get token usage breakdown by model."""
        usage = defaultdict(lambda: {'input': 0, 'output': 0})
        for call in self.calls:
            usage[call.model]['input'] += call.input_tokens
            usage[call.model]['output'] += call.output_tokens
        return dict(usage)
    
    def get_call_statistics(self) -> Dict:
        """Get statistics about API calls."""
        successful_calls = [c for c in self.calls if c.success]
        failed_calls = [c for c in self.calls if not c.success]
        total_cost = self.get_total_cost()
        
        return {
            'total_calls': len(self.calls),
            'successful_calls': len(successful_calls),
            'failed_calls': len(failed_calls),
            'success_rate': len(successful_calls) / len(self.calls) if self.calls else 0,
            'average_duration': sum(c.duration_seconds for c in self.calls) / len(self.calls) if self.calls else 0,
            'total_duration': sum(c.duration_seconds for c in self.calls),
            'avg_cost_per_call': total_cost / len(self.calls) if self.calls else 0
        }
    
    def export_report(self, format: str = 'json') -> str:
        """
        Export cost report.
        
        Args:
            format: Report format ('json' or 'text')
            
        Returns:
            Formatted report string
        """
        report_data = {
            'session_start': self.session_start.isoformat(),
            'session_duration_hours': (datetime.now() - self.session_start).total_seconds() / 3600,
            'total_cost_usd': self.get_total_cost(),
            'cost_by_model': self.get_cost_by_model(),
            'cost_by_provider': self.get_cost_by_provider(),
            'token_usage': self.get_token_usage(),
            'call_statistics': self.get_call_statistics(),
            'detailed_calls': [asdict(call) for call in self.calls]
        }
        
        if format == 'json':
            return json.dumps(report_data, indent=2)
        elif format == 'text':
            return self._format_text_report(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _format_text_report(self, data: Dict) -> str:
        """Format report as human-readable text."""
        lines = [
            "=" * 60,
            "CYPHERRAY COST REPORT",
            "=" * 60,
            f"\nSession Started: {data['session_start']}",
            f"Duration: {data['session_duration_hours']:.2f} hours",
            f"\n💰 TOTAL COST: ${data['total_cost_usd']:.4f}",
            "\n" + "-" * 60,
            "Cost by Provider:",
        ]
        
        for provider, cost in data['cost_by_provider'].items():
            lines.append(f"  {provider}: ${cost:.4f}")
        
        lines.extend([
            "\n" + "-" * 60,
            "Cost by Model:",
        ])
        
        for model, cost in data['cost_by_model'].items():
            lines.append(f"  {model}: ${cost:.4f}")
        
        lines.extend([
            "\n" + "-" * 60,
            "Token Usage:",
            f"  Total Input Tokens: {data['token_usage']['total_input_tokens']:,}",
            f"  Total Output Tokens: {data['token_usage']['total_output_tokens']:,}",
            f"  Total Tokens: {data['token_usage']['total_tokens']:,}",
            "\n" + "-" * 60,
            "Call Statistics:",
            f"  Total Calls: {data['call_statistics']['total_calls']}",
            f"  Successful: {data['call_statistics']['successful_calls']}",
            f"  Failed: {data['call_statistics']['failed_calls']}",
            f"  Success Rate: {data['call_statistics']['success_rate']:.1%}",
            f"  Avg Duration: {data['call_statistics']['average_duration']:.2f}s",
            "=" * 60
        ])
        
        return "\n".join(lines)
    
    def save_report(self, filename: Optional[str] = None):
        """Save cost report to file."""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"logs/cost_report_{timestamp}.json"
        
        Path(filename).parent.mkdir(exist_ok=True)
        
        with open(filename, 'w') as f:
            f.write(self.export_report(format='json'))
        
        print(f"Cost report saved to: {filename}")
    
    def reset(self):
        """Reset the cost tracker."""
        self.calls = []
        self.session_start = datetime.now()


# Example usage
if __name__ == "__main__":
    # Test the cost tracker
    tracker = CostTracker()
    
    # Simulate some API calls
    tracker.record_call("gpt-4o-mini", 1000, 500, 2.5)
    tracker.record_call("gpt-4o", 5000, 2000, 15.3)
    tracker.record_call("claude-3-5-sonnet-20241022", 8000, 3000, 20.1)
    tracker.record_call("gpt-4o", 3000, 1500, 12.0, success=False, error_message="Rate limit exceeded")
    
    # Print reports
    print("\n📊 TEXT REPORT:")
    print(tracker.export_report(format='text'))
    
    print("\n\n💾 Saving JSON report...")
    tracker.save_report()
    
    print("\n✅ Cost tracker test complete!")
