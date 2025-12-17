"""AI helpers (optional) for post-analysis insights.

This package is intentionally optional at runtime.
If required environment variables are missing, callers should treat AI features
as disabled.
"""

from .config import AiConfig, load_ai_config
from .insights import AiInsightsService

__all__ = ["AiConfig", "AiInsightsService", "load_ai_config"]
