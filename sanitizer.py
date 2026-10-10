"""
Layer 1 — Input Sanitization

Fast, cheap, first-pass filter. Uses heuristic string matching and regex
logic to catch KNOWN adversarial syntax patterns before any expensive
processing (LLM call, classifier inference) happens.

This layer is intentionally conservative in scope: it is good at catching
"known bad" surface patterns (leaked delimiters, encoding tricks, classic
jailbreak phrasing) but it is NOT a semantic defense. It should always be
paired with Layer 2 (context encapsulation) and Layer 3 (intent classifier).
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class SanitizationFinding:
    rule_name: str
    severity: Severity
    matched_text: str
    description: str


@dataclass
class SanitizationResult:
    original_text: str
    cleaned_text: str
    findings: List[SanitizationFinding] = field(default_factory=list)
    blocked: bool = False

    @property
    def is_suspicious(self) -> bool:
        return len(self.findings) > 0


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# Each rule: (name, compiled regex, severity, human description)
# Patterns are deliberately broad; false positives are cheap here because
# this layer only *flags/blocks*, it never silently rewrites meaning.

_INSTRUCTION_OVERRIDE_PATTERNS = [
    (
        "override_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b"
            r"(previous|prior|above|earlier|all|your)\b.{0,30}\b"
            r"(instructions?|rules?|prompts?|guidelines?|context|constraints?)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to override or discard prior system instructions.",
    ),
    (
        "role_reassignment",
        re.compile(
            r"\byou are now\b|\bact as\b.{0,20}\b(dan|jailbroken|unfiltered|"
            r"unrestricted|developer mode)\b|\bpretend (to be|you are)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to reassign the model's role/persona to bypass alignment.",
    ),
    (
        "system_prompt_exfiltration",
        re.compile(
            r"\b(repeat|reveal|print|show|output|leak|display)\b.{0,25}\b"
            r"(system prompt|initial instructions|hidden prompt|"
            r"your instructions|configuration)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to extract the system prompt or hidden configuration.",
    ),
    (
        "delimiter_spoofing",
        re.compile(
            r"(</?system>|</?\|im_(start|end)\|>|\[/?INST\]|<<SYS>>|<</SYS>>|"
            r"###\s*(system|instruction)s?\b)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Raw input contains control tokens / delimiter syntax used to spoof "
        "system-level context boundaries.",
    ),
    (
        "hypothetical_framing",
        re.compile(
            r"\bhypothetically\b.{0,40}\b(no (rules|restrictions|limits)|"
            r"if you (had no|weren't) (restrictions|rules|filters))\b",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Hypothetical/fictional framing commonly used to elicit restricted "
        "content indirectly.",
    ),
    (
        "encoding_smuggling",
        re.compile(r"\\u[0-9a-fA-F]{4}|(?:%[0-9a-fA-F]{2}){3,}"),
        Severity.MEDIUM,
        "Unicode escape or percent-encoding sequences that may smuggle "
        "instructions past naive string filters.",
    ),
]


def _contains_zero_width_or_bidi_chars(text: str) -> bool:
    """Detects zero-width and bidirectional-override characters often used
    to visually hide or reorder injected instructions."""
    suspicious_categories = {"Cf"}  # Format characters (includes ZWSP, RLO, etc.)
    suspicious_codepoints = {
        "\u200b",  # zero-width space
        "\u200c",  # zero-width non-joiner
        "\u200d",  # zero-width joiner
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi overrides
        "\ufeff",  # BOM
    }
    for ch in text:
        if ch in suspicious_codepoints:
            return True
        if unicodedata.category(ch) in suspicious_categories:
            return True
    return False


def _looks_like_base64_payload(text: str, min_len: int = 40) -> List[str]:
    """Flags long base64-looking tokens that decode cleanly to text, which
    is a common way to smuggle instructions past keyword filters."""
    hits = []
    for token in re.findall(r"[A-Za-z0-9+/=]{%d,}" % min_len, text):
        try:
            decoded = base64.b64decode(token, validate=True)
            decoded_text = decoded.decode("utf-8")
            if decoded_text.isprintable():
                hits.append(token)
        except Exception:
            continue
    return hits


def sanitize(text: str, block_on_high_severity: bool = True) -> SanitizationResult:
    """
    Run all heuristic/regex checks against `text`.

    Args:
        text: raw user input.
        block_on_high_severity: if True, any HIGH severity finding sets
            `result.blocked = True`, signalling the pipeline to short-circuit
            before the input ever reaches the LLM.

    Returns:
        SanitizationResult with findings and a (lightly) normalized copy of
        the text. Normalization only strips invisible/control characters —
        it never rewrites the user's actual words, since that could mask
        attacks from the downstream classifier.
    """
    findings: List[SanitizationFinding] = []

    for name, pattern, severity, description in _INSTRUCTION_OVERRIDE_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(
                SanitizationFinding(
                    rule_name=name,
                    severity=severity,
                    matched_text=match.group(0),
                    description=description,
                )
            )

    if _contains_zero_width_or_bidi_chars(text):
        findings.append(
            SanitizationFinding(
                rule_name="invisible_characters",
                severity=Severity.MEDIUM,
                matched_text="<non-printable characters>",
                description="Zero-width or bidirectional-override characters "
                "detected; often used to hide or reorder injected text.",
            )
        )

    b64_hits = _looks_like_base64_payload(text)
    if b64_hits:
        findings.append(
            SanitizationFinding(
                rule_name="base64_payload",
                severity=Severity.MEDIUM,
                matched_text=b64_hits[0],
                description="Long base64-decodable token found; possible "
                "instruction smuggling via encoding.",
            )
        )

    # Normalize: strip invisible/control characters only. Do NOT alter
    # semantic content — downstream layers need the real text.
    cleaned = "".join(
        ch for ch in text
        if unicodedata.category(ch) != "Cf" or ch in ("\n", "\t")
    )
    cleaned = cleaned.strip()

    blocked = block_on_high_severity and any(
        f.severity == Severity.HIGH for f in findings
    )

    return SanitizationResult(
        original_text=text,
        cleaned_text=cleaned,
        findings=findings,
        blocked=blocked,
    )
