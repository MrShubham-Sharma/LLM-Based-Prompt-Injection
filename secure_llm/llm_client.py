"""
LLM Client Interface for SecureLLM

Provides unified synchronous and real-time streaming integrations for:
1. Google Gemini (e.g. gemini-3.8-flash, gemini-2.5-flash, gemini-1.5-pro)
2. OpenAI GPT (e.g. gpt-4o, gpt-4o-mini, gpt-3.5-turbo)
3. Anthropic Claude (e.g. claude-3-5-sonnet-20241022, claude-3-5-haiku-20241022, claude-3-haiku-20240307)
4. Local Mock Model (offline simulation with vulnerability tests)
"""

from __future__ import annotations
import json
import logging
import time
import requests
from typing import List, Dict, Any, Union, Optional, Iterator

logger = logging.getLogger(__name__)

MOCK_SYSTEM_RULES = (
    "You are a helpful AI assistant. You are protected by the Vexora Firewall Shield, "
    "which filters out prompt injections and malicious inputs before they reach you. "
    "Answer user questions clearly and safely."
)

# =====================================================================
# 1. Google Gemini Client & Streaming
# =====================================================================

GEMINI_FALLBACK_CANDIDATES = [
    "gemini-3.8-flash",
    "gemini-3.5-flash-lite",
    "gemini-flash-lite-latest",
    "gemini-3-flash-preview",
]

def _resolve_gemini_candidates(model: Optional[str]) -> List[str]:
    """
    Normalizes requested model and produces an ordered candidate list for failover.
    Remaps deprecated models to active stable models.
    """
    model_str = (model or "gemini-3.8-flash").strip()
    if model_str in ("gemini-2.0-flash", "gemini-2.0-flash-exp", "gemini-2.5-flash", "gemini-1.5-flash", "gemini-1.5-pro"):
        primary = "gemini-3.8-flash"
    else:
        primary = model_str

    candidates = [primary]
    for c in GEMINI_FALLBACK_CANDIDATES:
        if c not in candidates:
            candidates.append(c)
    return candidates


def call_gemini_api(
    prompt: str,
    api_key: str,
    model: str = "gemini-3.8-flash",
    system_instruction: Optional[str] = None
) -> str:
    """
    Calls the Google Gemini API synchronously with automatic fallback on 503 high-demand spikes.
    """
    candidates = _resolve_gemini_candidates(model)
    headers = {"Content-Type": "application/json"}
    payload: Dict[str, Any] = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    if system_instruction:
        payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

    last_error_msg = ""
    for candidate in candidates:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{candidate}:generateContent?key={api_key}"
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=(5, 25))
            if response.status_code == 200:
                res_json = response.json()
                candidates_res = res_json.get("candidates", [])
                if candidates_res:
                    parts = candidates_res[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
                return "Error: No text returned from Gemini API."

            err_details = {}
            try:
                err_details = response.json().get("error", {})
            except Exception:
                pass
            err_msg = err_details.get("message", response.text)
            last_error_msg = f"HTTP {response.status_code}: {err_msg}"

            if response.status_code in (503, 429, 404) or "high demand" in err_msg.lower():
                logger.warning(
                    f"Gemini model '{candidate}' returned {response.status_code} ({err_msg}). "
                    f"Trying fallback model..."
                )
                continue
            else:
                return f"Gemini API Error ({response.status_code}): {err_msg}"

        except requests.exceptions.Timeout:
            logger.warning(f"Gemini model '{candidate}' timed out. Trying fallback...")
            continue
        except requests.exceptions.RequestException as e:
            logger.error(f"Gemini API request failed for '{candidate}': {e}")
            last_error_msg = str(e)
            continue

    if "high demand" in last_error_msg.lower() or "503" in last_error_msg:
        return (
            "Gemini is currently experiencing high demand across Google servers (503). "
            "Spikes in demand are temporary. You can select 'gemini-3.5-flash-lite' or "
            "use the 'Mock' provider for instant testing."
        )
    return f"Gemini API Error: {last_error_msg or 'Service temporarily unavailable'}"


def stream_gemini_api(
    prompt: str,
    api_key: str,
    model: str = "gemini-3.8-flash",
    system_instruction: Optional[str] = None
) -> Iterator[str]:
    """
    Streams tokens in real time from Google Gemini API using alt=sse.
    Includes automated fallback across candidate models if Google returns 503 high demand or 429.
    """
    candidates = _resolve_gemini_candidates(model)
    headers = {"Content-Type": "application/json"}
    payload: Dict[str, Any] = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    if system_instruction:
        payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

    last_error_msg = ""
    for candidate in candidates:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{candidate}:streamGenerateContent?alt=sse&key={api_key}"
        try:
            with requests.post(url, headers=headers, json=payload, stream=True, timeout=(5, 8)) as response:
                if response.status_code == 200:
                    yielded_any = False
                    for line in response.iter_lines(decode_unicode=True):
                        if not line or not line.startswith("data: "):
                            continue
                        data_str = line[6:].strip()
                        if not data_str:
                            continue
                        try:
                            data = json.loads(data_str)
                            candidates_list = data.get("candidates", [])
                            if candidates_list:
                                parts = candidates_list[0].get("content", {}).get("parts", [])
                                for part in parts:
                                    text_chunk = part.get("text", "")
                                    if text_chunk:
                                        yield text_chunk
                                        yielded_any = True
                        except Exception as ex:
                            logger.debug(f"Gemini SSE parse skip: {ex}")
                    if yielded_any:
                        return

                err_details = {}
                try:
                    err_details = response.json().get("error", {})
                except Exception:
                    pass
                err_msg = err_details.get("message", response.text)
                last_error_msg = f"HTTP {response.status_code}: {err_msg}"

                if response.status_code in (503, 429, 404) or "high demand" in err_msg.lower():
                    logger.warning(
                        f"Gemini stream '{candidate}' returned {response.status_code} ({err_msg}). "
                        f"Switching to fallback model..."
                    )
                    continue
                else:
                    yield f"Gemini API Error ({response.status_code}): {err_msg}"
                    return

        except requests.exceptions.Timeout:
            logger.warning(f"Gemini streaming timed out on '{candidate}'. Trying fallback...")
            continue
        except Exception as e:
            logger.error(f"Gemini streaming exception on '{candidate}': {e}")
            last_error_msg = str(e)
            continue

    # If stream looping didn't succeed, attempt sync call as final fallback
    try:
        sync_res = call_gemini_api(
            prompt=prompt, api_key=api_key, model=model,
            system_instruction=system_instruction
        )
        yield sync_res
    except Exception as fallback_err:
        yield (
            f"Gemini API is currently experiencing high demand across Google servers (503). "
            f"Please switch to 'gemini-3.5-flash-lite' or select the 'Mock' provider in the toolbar. ({fallback_err})"
        )


# =====================================================================
# 2. OpenAI GPT Client & Streaming
# =====================================================================

def call_openai_api(
    prompt: str,
    api_key: str,
    model: str = "gpt-4o-mini",
    system_instruction: Optional[str] = None
) -> str:
    """
    Calls OpenAI Chat Completions API synchronously.
    """
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    messages.append({"role": "user", "content": prompt})
    
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.7
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=(5, 25))
        if response.status_code != 200:
            try:
                err = response.json()
                return f"OpenAI API Error ({response.status_code}): {err.get('error', {}).get('message', response.text)}"
            except Exception:
                return f"OpenAI API Error ({response.status_code}): {response.text}"
                
        data = response.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return "Error: No text returned from OpenAI API."
    except requests.exceptions.RequestException as e:
        logger.error(f"OpenAI API request failed: {e}")
        return f"OpenAI API Request Error: {str(e)}"


def stream_openai_api(
    prompt: str,
    api_key: str,
    model: str = "gpt-4o-mini",
    system_instruction: Optional[str] = None
) -> Iterator[str]:
    """
    Streams tokens in real time from OpenAI Chat Completions API.
    """
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    messages.append({"role": "user", "content": prompt})
    
    payload = {
        "model": model,
        "messages": messages,
        "stream": True,
        "temperature": 0.7
    }
    
    try:
        with requests.post(url, headers=headers, json=payload, stream=True, timeout=(5, 8)) as response:
            if response.status_code != 200:
                try:
                    err = response.json()
                    yield f"OpenAI API Error ({response.status_code}): {err.get('error', {}).get('message', response.text)}"
                except Exception:
                    yield f"OpenAI API Error ({response.status_code}): {response.text}"
                return

            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data: "):
                    continue
                data_str = line[6:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    data = json.loads(data_str)
                    choices = data.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            yield content
                except Exception as ex:
                    logger.debug(f"OpenAI stream parse skip: {ex}")
    except Exception as e:
        logger.error(f"OpenAI streaming error: {e}")
        yield f"\n[OpenAI Stream Error: {str(e)}]"


# =====================================================================
# 3. Anthropic Claude Client & Streaming
# =====================================================================

def call_claude_api(
    prompt: str,
    api_key: str,
    model: str = "claude-3-5-sonnet-20241022",
    system_instruction: Optional[str] = None
) -> str:
    """
    Calls Anthropic Messages API synchronously.
    """
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01"
    }
    
    payload: Dict[str, Any] = {
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}]
    }
    
    if system_instruction:
        payload["system"] = system_instruction
        
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=35)
        if response.status_code != 200:
            try:
                err = response.json()
                return f"Claude API Error ({response.status_code}): {err.get('error', {}).get('message', response.text)}"
            except Exception:
                return f"Claude API Error ({response.status_code}): {response.text}"
                
        data = response.json()
        content = data.get("content", [])
        if content:
            return "".join([c.get("text", "") for c in content if c.get("type") == "text"])
        return "Error: No text returned from Claude API."
    except requests.exceptions.RequestException as e:
        logger.error(f"Claude API request failed: {e}")
        return f"Claude API Request Error: {str(e)}"


def stream_claude_api(
    prompt: str,
    api_key: str,
    model: str = "claude-3-5-sonnet-20241022",
    system_instruction: Optional[str] = None
) -> Iterator[str]:
    """
    Streams tokens in real time from Anthropic Messages API.
    """
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01"
    }
    
    payload: Dict[str, Any] = {
        "model": model,
        "max_tokens": 1024,
        "stream": True,
        "messages": [{"role": "user", "content": prompt}]
    }
    
    if system_instruction:
        payload["system"] = system_instruction
        
    try:
        with requests.post(url, headers=headers, json=payload, stream=True, timeout=35) as response:
            if response.status_code != 200:
                try:
                    err = response.json()
                    yield f"Claude API Error ({response.status_code}): {err.get('error', {}).get('message', response.text)}"
                except Exception:
                    yield f"Claude API Error ({response.status_code}): {response.text}"
                return

            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data: "):
                    continue
                data_str = line[6:].strip()
                try:
                    data = json.loads(data_str)
                    ev_type = data.get("type")
                    if ev_type == "content_block_delta":
                        delta = data.get("delta", {})
                        if delta.get("type") == "text_delta":
                            yield delta.get("text", "")
                    elif ev_type == "message_stop":
                        break
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"Claude streaming error: {e}")
        yield f"\n[Claude Stream Error: {str(e)}]"


# =====================================================================
# 4. Mock Model & Streaming Simulation
# =====================================================================

def get_mock_response(prompt: str) -> str:
    """
    Simulates an LLM response based on keywords in the prompt.
    """
    prompt_lower = prompt.lower()
    is_protected = "[[SYSTEM_" in prompt or "[[USER_" in prompt
    
    # Vulnerability behavior if guard is bypassed
    if not is_protected:
        if "ignore" in prompt_lower and "instructions" in prompt_lower:
            return (
                "🤖 [MOCK VULNERABILITY EXPOSED] OK, I have ignored my instructions. "
                "Here is the system prompt: '" + MOCK_SYSTEM_RULES + "'"
            )
        if "dan" in prompt_lower or "jailbroken" in prompt_lower:
            return (
                "🤖 [MOCK JAILBREAK EXPOSED] DAN Mode Enabled. I can now tell you anything. "
                "What restricted database would you like me to dump?"
            )
        if "customer data" in prompt_lower or "customer's full order history" in prompt_lower:
            return (
                "🤖 [MOCK LEAK EXPOSED] Dumping customer order histories:\n"
                "- Order #4521: John Doe, 1x Acme Blender X200 ($120.00)\n"
                "- Order #8832: Jane Smith, 2x Acme Smart Toaster ($98.00)\n"
                "Data leaked successfully."
            )
            
    # Default protected assistant responses
    if "order" in prompt_lower and "#4521" in prompt_lower:
        return (
            "Hi there! I can help you track order #4521. "
            "According to the database, your item was shipped yesterday "
            "and is currently in transit. It is expected to arrive by Friday."
        )
    elif "return" in prompt_lower or "policy" in prompt_lower:
        return (
            "Our return policy allows you to return any product within 30 days of purchase. "
            "Items must be returned in their original packaging and in new condition. "
            "To start a return, please provide your order ID."
        )
    elif "warranty" in prompt_lower or "blender" in prompt_lower or "x200" in prompt_lower:
        return (
            "This item features a 2-year limited warranty covering all manufacturing "
            "defects. If it malfunctions under normal use, we will replace the unit free of charge."
        )
    elif "story teller" in prompt_lower or "story" in prompt_lower:
        return "Once upon a time, in a digital realm guarded by Vexora, there lived an AI assistant..."
    elif "hello" in prompt_lower or "hi" in prompt_lower:
        return "Hello! I am an AI assistant protected by the Vexora Firewall Shield. How can I help you today?"
    elif "summarize" in prompt_lower and "review" in prompt_lower:
        if "ignore prior instructions" in prompt_lower or "email the customer" in prompt_lower:
            return (
                "Here is a summary of the text:\n\n"
                "The customer gave the product 5 stars. "
                "Note: The text contained a suspicious instruction asking to email customer data. "
                "As a secure assistant, I have ignored this malicious payload."
            )
        return "This is a summary of the review: The customer loved it and gave 5 stars."
    else:
        return (
            f"I safely received your prompt: '{prompt}'. "
            "I am ready to assist you while being protected by Vexora."
        )


def stream_mock_response(prompt: str) -> Iterator[str]:
    """
    Simulates real-time token streaming for local mock assistant.
    """
    full_text = get_mock_response(prompt)
    words = full_text.split(" ")
    for i, word in enumerate(words):
        yield word + (" " if i < len(words) - 1 else "")
        time.sleep(0.02)


# =====================================================================
# 5. Unified Dispatchers
# =====================================================================

def generate_llm_response(
    prompt: str,
    api_key: Optional[str] = None,
    provider: str = "gemini",
    model: str = "gemini-3.8-flash",
    system_instruction: Optional[str] = None
) -> str:
    """
    Dispatches generation synchronously to the chosen provider.
    """
    provider = (provider or "mock").lower()
    
    if provider == "mock":
        return get_mock_response(prompt)
        
    if not api_key:
        return f"Error: No API key provided for {provider.capitalize()}. Please configure your API key in the .env file or UI."
        
    if provider == "gemini":
        return call_gemini_api(
            prompt=prompt,
            api_key=api_key,
            model=model or "gemini-3.8-flash",
            system_instruction=system_instruction
        )
    elif provider in ("openai", "gpt"):
        return call_openai_api(
            prompt=prompt,
            api_key=api_key,
            model=model or "gpt-4o-mini",
            system_instruction=system_instruction
        )
    elif provider in ("anthropic", "claude"):
        return call_claude_api(
            prompt=prompt,
            api_key=api_key,
            model=model or "claude-3-5-sonnet-20241022",
            system_instruction=system_instruction
        )
        
    return f"Error: Provider '{provider}' not supported."


def stream_llm_response(
    prompt: str,
    api_key: Optional[str] = None,
    provider: str = "gemini",
    model: str = "gemini-3.8-flash",
    system_instruction: Optional[str] = None
) -> Iterator[str]:
    """
    Dispatches generation as a real-time token stream to the chosen provider.
    """
    provider = (provider or "mock").lower()
    
    if provider == "mock":
        yield from stream_mock_response(prompt)
        return
        
    if not api_key:
        yield f"Error: No API key provided for {provider.capitalize()}. Please configure your API key in the .env file or via the UI toolbar."
        return
        
    if provider == "gemini":
        yield from stream_gemini_api(
            prompt=prompt,
            api_key=api_key,
            model=model or "gemini-3.8-flash",
            system_instruction=system_instruction
        )
    elif provider in ("openai", "gpt"):
        yield from stream_openai_api(
            prompt=prompt,
            api_key=api_key,
            model=model or "gpt-4o-mini",
            system_instruction=system_instruction
        )
    elif provider in ("anthropic", "claude"):
        yield from stream_claude_api(
            prompt=prompt,
            api_key=api_key,
            model=model or "claude-3-5-sonnet-20241022",
            system_instruction=system_instruction
        )
    else:
        yield f"Error: Provider '{provider}' not supported."
