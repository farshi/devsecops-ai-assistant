"""Unified LLM client — routes to Claude or GPT based on configuration."""

import json
import logging
import os

logger = logging.getLogger(__name__)


def call(system_prompt: str, user_message: str, provider: str = "claude") -> str:
    """Send a prompt to the configured LLM and return text response.

    Args:
        system_prompt: System/instruction prompt
        user_message: User message content
        provider: "claude" or "openai" (reads from env if not specified)

    Returns:
        LLM response text

    Raises:
        RuntimeError: if API key is missing or provider is unsupported
    """
    if provider == "claude":
        return _call_claude(system_prompt, user_message)
    elif provider in ("openai", "gpt"):
        return _call_openai(system_prompt, user_message)
    else:
        raise RuntimeError(
            f"Unsupported LLM provider: {provider}. Use 'claude' or 'openai'."
        )


def _call_claude(system_prompt: str, user_message: str) -> str:
    """Call Anthropic Claude API."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY environment variable is not set."
        )

    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=os.environ.get("PATCHPILOT_CLAUDE_MODEL", "claude-sonnet-4-20250514"),
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )
    return message.content[0].text


def _call_openai(system_prompt: str, user_message: str) -> str:
    """Call OpenAI GPT API using urllib (no openai SDK dependency)."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY environment variable is not set."
        )

    import urllib.error
    import urllib.request

    model = os.environ.get("PATCHPILOT_OPENAI_MODEL", "gpt-4o-mini")

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "temperature": 0.3,
    })

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload.encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]
    except (urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"OpenAI API error: {exc}")
