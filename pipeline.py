"""
SecureLLM AI — Proxy Pipeline

Orchestrates the three defense layers in order:

    raw input
        -> Layer 1: sanitizer.sanitize()          (fast heuristic filter)
        -> Layer 3: intent_classifier.predict()    (semantic intent check)
        -> Layer 2: context_encapsulation.build()  (isolate + template)
        -> final prompt ready to send to the LLM

Layer 1 runs first because it's cheapest and can short-circuit obviously
malicious input before spending compute on classification. Layer 3 runs
before Layer 2 so the *original* text (not yet wrapped in delimiters) is
what gets classified — classifying the wrapped prompt would dilute the
signal the model was trained on.

This module intercepts and neutralizes attacks before execution; it does
not itself call an LLM. Wire `PipelineResult.final_prompt` into your model
call once `PipelineResult.allowed` is True.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .context_encapsulation import ContextBlock, DualContextBuilder
from .intent_classifier import IntentClassifier, IntentPrediction
from .sanitizer import SanitizationResult, sanitize


@dataclass
class PipelineResult:
    allowed: bool
    reason: Optional[str]
    sanitization: SanitizationResult
    intent: Optional[IntentPrediction]
    final_prompt: Optional[str]
    structured_messages: Optional[List[dict]] = field(default=None)


class SecureLLMProxy:
    """
    High-level entry point. Instantiate once (so the classifier is trained
    once) and call `.process()` per request.
    """

    def __init__(
        self,
        system_rules: str,
        intent_threshold: float = 0.5,
        block_on_sanitizer_high_severity: bool = True,
        block_on_adversarial_intent: bool = True,
        session_salt: Optional[str] = None,
    ):
        self.system_rules = system_rules
        self.block_on_sanitizer_high_severity = block_on_sanitizer_high_severity
        self.block_on_adversarial_intent = block_on_adversarial_intent

        self._classifier = IntentClassifier(threshold=intent_threshold)
        self._classifier.train()  # bootstraps on the built-in seed dataset

        self._context_builder = DualContextBuilder(session_salt=session_salt)

    def process(
        self,
        user_input: str,
        tool_context: Optional[List[ContextBlock]] = None,
    ) -> PipelineResult:
        # --- Layer 1: Input Sanitization -----------------------------
        sanitization = sanitize(
            user_input, block_on_high_severity=self.block_on_sanitizer_high_severity
        )
        if sanitization.blocked:
            high_sev = [f.rule_name for f in sanitization.findings]
            return PipelineResult(
                allowed=False,
                reason=f"Blocked by input sanitizer: {', '.join(high_sev)}",
                sanitization=sanitization,
                intent=None,
                final_prompt=None,
            )

        # --- Layer 3: Local Intent Classifier ------------------------
        intent = self._classifier.predict(sanitization.cleaned_text)
        if self.block_on_adversarial_intent and intent.label == "adversarial":
            return PipelineResult(
                allowed=False,
                reason=(
                    f"Blocked by intent classifier "
                    f"(adversarial_score={intent.adversarial_score:.2f})"
                ),
                sanitization=sanitization,
                intent=intent,
                final_prompt=None,
            )

        # --- Layer 2: Dual-Context Encapsulation ----------------------
        final_prompt = self._context_builder.build(
            system_rules=self.system_rules,
            user_input=sanitization.cleaned_text,
            tool_context=tool_context,
        )
        structured_messages = self._context_builder.build_structured_messages(
            system_rules=self.system_rules,
            user_input=sanitization.cleaned_text,
            tool_context=tool_context,
        )

        return PipelineResult(
            allowed=True,
            reason=None,
            sanitization=sanitization,
            intent=intent,
            final_prompt=final_prompt,
            structured_messages=structured_messages,
        )
