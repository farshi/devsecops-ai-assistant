"""Backward-compatible Claude client — delegates to llm_client."""

from agent.llm_client import call as _call


def call(system_prompt: str, user_message: str) -> str:
    """Send a single-turn message to Claude. Legacy interface."""
    return _call(system_prompt, user_message, provider="claude")
