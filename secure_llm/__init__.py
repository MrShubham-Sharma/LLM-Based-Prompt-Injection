"""
SecureLLM AI — Multi-layered proxy defense framework against prompt injection.

Layers:
    1. sanitizer.py              -> Input Sanitization (heuristic / regex)
    2. context_encapsulation.py  -> Dual-Context Encapsulation (prompt templating)
    3. intent_classifier.py      -> Local Intent Classifier (lightweight ML model)
    4. pipeline.py                -> Orchestrates all three layers into one proxy call
"""

from .pipeline import SecureLLMProxy, PipelineResult

__all__ = ["SecureLLMProxy", "PipelineResult"]
__version__ = "0.1.0"
