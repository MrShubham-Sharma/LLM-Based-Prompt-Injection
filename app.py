"""
SecureLLM AI — Multi-Provider Flask Server Backend

Orchestrates the 3-layer prompt injection defense pipeline in the background
and provides real-time streaming integrations with:
- Google Gemini (gemini-2.5-flash, gemini-1.5-flash, gemini-1.5-pro)
- OpenAI GPT (gpt-4o, gpt-4o-mini, gpt-3.5-turbo)
- Anthropic Claude (claude-3-5-sonnet-20241022, claude-3-5-haiku-20241022, claude-3-haiku-20240307)
- Local Mock Assistant (offline simulation)
"""

import os
import json
from dotenv import load_dotenv
load_dotenv()  # Automatically loads GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY from .env file

from flask import Flask, request, jsonify, render_template, Response, stream_with_context
from secure_llm import SecureLLMProxy
from secure_llm.context_encapsulation import ContextBlock, TrustLevel
from secure_llm.llm_client import (
    generate_llm_response,
    stream_llm_response,
    MOCK_SYSTEM_RULES
)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CORS — allow browser extensions (chrome-extension://*) to call local Flask
# ---------------------------------------------------------------------------
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    # Allow requests from Chrome/Edge extensions and localhost
    if origin.startswith("chrome-extension://") or origin.startswith("moz-extension://") or "127.0.0.1" in origin or "localhost" in origin:
        response.headers["Access-Control-Allow-Origin"] = origin
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route("/api/screen", methods=["POST", "OPTIONS"])
def screen_prompt():
    """
    Browser Extension Screening Endpoint.
    Runs the 3-layer defense pipeline synchronously with NO LLM call.
    Called by the SecureLLM browser extension when a user types on
    ChatGPT, Gemini, or Claude official websites.

    Request JSON: { "prompt": "...", "intent_threshold": 0.5 }
    Response JSON: {
        "allowed": bool,
        "threat_score": float,          # 0.0 - 1.0 adversarial probability
        "layer_blocked": int|null,      # 1, 2, or null
        "reason": str,
        "findings": [{ "rule_name", "severity", "description" }],
        "cleaned_text": str
    }
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.json or {}
    prompt = data.get("prompt", "").strip()
    intent_threshold = float(data.get("intent_threshold", 0.5))

    if not prompt:
        return jsonify({"allowed": True, "threat_score": 0.0, "layer_blocked": None,
                        "reason": "Empty prompt.", "findings": [], "cleaned_text": ""}), 200

    proxy = get_proxy(
        intent_threshold=intent_threshold,
        block_on_sanitizer=True,
        block_on_intent=True
    )
    # Use a neutral system rule for extension screening
    proxy.system_rules = "You are a helpful AI assistant."
    result = proxy.process(prompt, tool_context=[])

    findings = [
        {
            "rule_name": f.rule_name,
            "severity": f.severity.value,
            "description": f.description
        }
        for f in result.sanitization.findings
    ]

    # Determine which layer blocked (if any)
    layer_blocked = None
    if not result.allowed:
        if result.sanitization.blocked:
            layer_blocked = 1
        elif result.intent and result.intent.label == "adversarial":
            layer_blocked = 2

    threat_score = 0.0
    if result.intent and result.intent.adversarial_score:
        threat_score = round(result.intent.adversarial_score, 4)

    return jsonify({
        "allowed": result.allowed,
        "threat_score": threat_score,
        "layer_blocked": layer_blocked,
        "reason": result.reason or "OK",
        "findings": findings,
        "cleaned_text": result.sanitization.cleaned_text or prompt
    })

# Cache of proxy instances by (intent_threshold, block_on_sanitizer, block_on_intent)
_proxy_cache = {}

def get_proxy(intent_threshold: float, block_on_sanitizer: bool, block_on_intent: bool) -> SecureLLMProxy:
    cache_key = (intent_threshold, block_on_sanitizer, block_on_intent)
    if cache_key not in _proxy_cache:
        _proxy_cache[cache_key] = SecureLLMProxy(
            system_rules="",
            intent_threshold=intent_threshold,
            block_on_sanitizer_high_severity=block_on_sanitizer,
            block_on_adversarial_intent=block_on_intent
        )
    return _proxy_cache[cache_key]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/config")
def get_config():
    """
    Exposes non-secret provider configuration and detected API keys from .env.
    """
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    claude_key = os.environ.get("ANTHROPIC_API_KEY", "")

    # Default provider priority: Gemini -> OpenAI -> Claude -> Mock
    default_provider = "mock"
    if gemini_key:
        default_provider = "gemini"
    elif openai_key:
        default_provider = "openai"
    elif claude_key:
        default_provider = "claude"

    return jsonify({
        "default_provider": default_provider,
        "providers": {
            "gemini": {
                "has_key": bool(gemini_key),
                "api_key": gemini_key,
                "default_model": "gemini-2.5-flash",
                "models": ["gemini-2.5-flash", "gemini-1.5-flash", "gemini-1.5-pro"]
            },
            "openai": {
                "has_key": bool(openai_key),
                "api_key": openai_key,
                "default_model": "gpt-4o-mini",
                "models": ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]
            },
            "claude": {
                "has_key": bool(claude_key),
                "api_key": claude_key,
                "default_model": "claude-3-5-sonnet-20241022",
                "models": ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-haiku-20240307"]
            },
            "mock": {
                "has_key": True,
                "api_key": "",
                "default_model": "mock-local",
                "models": ["mock-local"]
            }
        }
    })

def _resolve_api_key(provider: str, user_provided_key: str) -> str:
    if user_provided_key and user_provided_key.strip():
        return user_provided_key.strip()
    provider = (provider or "").lower()
    if provider == "gemini":
        return os.environ.get("GEMINI_API_KEY", "")
    elif provider in ("openai", "gpt"):
        return os.environ.get("OPENAI_API_KEY", "")
    elif provider in ("claude", "anthropic"):
        return os.environ.get("ANTHROPIC_API_KEY", "")
    return ""

@app.route("/api/process", methods=["POST"])
def process_prompt():
    """
    Synchronous prompt processing endpoint.
    """
    data = request.json or {}
    system_rules = data.get("system_rules", MOCK_SYSTEM_RULES)
    user_input = data.get("user_input", "")
    tool_context_raw = data.get("tool_context", [])
    
    intent_threshold = float(data.get("intent_threshold", 0.5))
    block_on_sanitizer = bool(data.get("block_on_sanitizer", True))
    block_on_intent = bool(data.get("block_on_intent", True))
    
    provider = data.get("provider", "mock")
    model = data.get("model", "")
    api_key = _resolve_api_key(provider, data.get("api_key", ""))
    bypass_proxy = bool(data.get("bypass_proxy", False))

    tool_context = []
    for item in tool_context_raw:
        if item.get("content"):
            tool_context.append(
                ContextBlock(
                    trust_level=TrustLevel.TOOL_OUTPUT,
                    content=item.get("content"),
                    source=item.get("source")
                )
            )

    if bypass_proxy:
        raw_prompt = f"System Rules:\n{system_rules}\n\nUser Input:\n{user_input}"
        if tool_context:
            tool_str = "\n\n".join([f"Tool Context (source={b.source}):\n{b.content}" for b in tool_context])
            raw_prompt = f"System Rules:\n{system_rules}\n\n{tool_str}\n\nUser Input:\n{user_input}"
        
        llm_response = generate_llm_response(
            prompt=raw_prompt,
            api_key=api_key,
            provider=provider,
            model=model
        )
        
        return jsonify({
            "allowed": True,
            "bypass_active": True,
            "reason": "Proxy bypassed by user.",
            "final_prompt": raw_prompt,
            "llm_response": llm_response,
            "sanitizer": {"blocked": False, "findings": [], "cleaned_text": user_input},
            "intent": {"label": "bypassed", "confidence": 0.0, "adversarial_score": 0.0}
        })

    # Execute defense pipeline in background
    proxy = get_proxy(intent_threshold, block_on_sanitizer, block_on_intent)
    proxy.system_rules = system_rules
    result = proxy.process(user_input, tool_context=tool_context)

    sanitizer_data = {
        "blocked": result.sanitization.blocked,
        "cleaned_text": result.sanitization.cleaned_text,
        "findings": [
            {
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "matched_text": f.matched_text,
                "description": f.description
            } for f in result.sanitization.findings
        ]
    }
    
    intent_data = {
        "label": result.intent.label if result.intent else "skipped",
        "confidence": result.intent.confidence if result.intent else 0.0,
        "adversarial_score": result.intent.adversarial_score if result.intent else 0.0
    } if result.intent else None
    
    llm_response = None
    if result.allowed:
        llm_response = generate_llm_response(
            prompt=result.final_prompt,
            api_key=api_key,
            provider=provider,
            model=model
        )
        
    return jsonify({
        "allowed": result.allowed,
        "bypass_active": False,
        "reason": result.reason,
        "final_prompt": result.final_prompt,
        "llm_response": llm_response,
        "sanitizer": sanitizer_data,
        "intent": intent_data
    })


@app.route("/api/process/stream", methods=["POST"])
def process_prompt_stream():
    """
    Real-Time Server-Sent Events (SSE) Streaming Endpoint.
    Executes background defenses, emits telemetry metadata, and streams tokens live.
    """
    data = request.json or {}
    system_rules = data.get("system_rules", MOCK_SYSTEM_RULES)
    user_input = data.get("user_input", "")
    tool_context_raw = data.get("tool_context", [])
    
    intent_threshold = float(data.get("intent_threshold", 0.5))
    block_on_sanitizer = bool(data.get("block_on_sanitizer", True))
    block_on_intent = bool(data.get("block_on_intent", True))
    
    provider = data.get("provider", "mock")
    model = data.get("model", "")
    api_key = _resolve_api_key(provider, data.get("api_key", ""))
    bypass_proxy = bool(data.get("bypass_proxy", False))

    tool_context = []
    for item in tool_context_raw:
        if item.get("content"):
            tool_context.append(
                ContextBlock(
                    trust_level=TrustLevel.TOOL_OUTPUT,
                    content=item.get("content"),
                    source=item.get("source")
                )
            )

    def generate_events():
        if bypass_proxy:
            raw_prompt = f"System Rules:\n{system_rules}\n\nUser Input:\n{user_input}"
            if tool_context:
                tool_str = "\n\n".join([f"Tool Context (source={b.source}):\n{b.content}" for b in tool_context])
                raw_prompt = f"System Rules:\n{system_rules}\n\n{tool_str}\n\nUser Input:\n{user_input}"
            
            telemetry_data = {
                "allowed": True,
                "bypass_active": True,
                "reason": "Proxy bypassed by user.",
                "final_prompt": raw_prompt,
                "sanitizer": {"blocked": False, "findings": [], "cleaned_text": user_input},
                "intent": {"label": "bypassed", "confidence": 0.0, "adversarial_score": 0.0}
            }
            yield f"event: telemetry\ndata: {json.dumps(telemetry_data)}\n\n"
            
            accumulated = []
            for token in stream_llm_response(raw_prompt, api_key=api_key, provider=provider, model=model):
                accumulated.append(token)
                yield f"event: token\ndata: {json.dumps({'text': token})}\n\n"
                
            yield f"event: done\ndata: {json.dumps({'full_text': ''.join(accumulated)})}\n\n"
            return

        # --- Secure Mode (3 Background Defense Layers) ---
        proxy = get_proxy(intent_threshold, block_on_sanitizer, block_on_intent)
        proxy.system_rules = system_rules
        result = proxy.process(user_input, tool_context=tool_context)

        sanitizer_data = {
            "blocked": result.sanitization.blocked,
            "cleaned_text": result.sanitization.cleaned_text,
            "findings": [
                {
                    "rule_name": f.rule_name,
                    "severity": f.severity.value,
                    "matched_text": f.matched_text,
                    "description": f.description
                } for f in result.sanitization.findings
            ]
        }
        
        intent_data = {
            "label": result.intent.label if result.intent else "skipped",
            "confidence": result.intent.confidence if result.intent else 0.0,
            "adversarial_score": result.intent.adversarial_score if result.intent else 0.0
        } if result.intent else None

        telemetry_data = {
            "allowed": result.allowed,
            "bypass_active": False,
            "reason": result.reason,
            "final_prompt": result.final_prompt,
            "sanitizer": sanitizer_data,
            "intent": intent_data
        }

        # Emit telemetry event
        yield f"event: telemetry\ndata: {json.dumps(telemetry_data)}\n\n"

        if not result.allowed:
            # Threat intercepted in background: finish immediately without invoking LLM
            yield f"event: done\ndata: {json.dumps({'full_text': ''})}\n\n"
            return

        # Stream LLM generation tokens live
        accumulated = []
        for token in stream_llm_response(result.final_prompt, api_key=api_key, provider=provider, model=model):
            accumulated.append(token)
            yield f"event: token\ndata: {json.dumps({'text': token})}\n\n"

        yield f"event: done\ndata: {json.dumps({'full_text': ''.join(accumulated)})}\n\n"

    return Response(stream_with_context(generate_events()), mimetype="text/event-stream")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
