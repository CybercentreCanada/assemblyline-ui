"""Pydantic AI agent for Assemblyline assistant."""

import asyncio
import os

import yaml
from openai import AsyncOpenAI
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

# Environment-driven configuration
LLM_MODEL = os.environ.get("LLM_MODEL", "@anthropic/claude-sonnet-4-6")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", None)
PORTKEY_API_KEY = os.environ.get("PORTKEY_API_KEY", None)
PORTKEY_GATEWAY_URL = os.environ.get("PORTKEY_GATEWAY_URL", "")
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", None)


def _get_ai_backends():
    # Lazy import to avoid circular dependency: assemblyline_ui.config imports build_agent from here.
    from assemblyline_ui.config import config  # noqa: PLC0415
    return config.ui.ai_backends.function_params


def _build_system_prompt(template: str, lang: str = "english", extra_context: str = "") -> str:
    """Substitute $(LANG) and $(EXTRA_CONTEXT) placeholders in a config system prompt."""
    return template.replace("$(LANG)", lang).replace("$(EXTRA_CONTEXT)", extra_context)


def _build_model():
    """Build the LLM model using Portkey gateway or a custom base URL."""
    if PORTKEY_API_KEY:
        openai_client = AsyncOpenAI(
            base_url=PORTKEY_GATEWAY_URL,
            api_key="unused",
            default_headers={"x-portkey-api-key": PORTKEY_API_KEY},
            timeout=120.0,
        )
        provider = OpenAIProvider(openai_client=openai_client)
        return OpenAIChatModel(model_name=LLM_MODEL, provider=provider)
    if LLM_BASE_URL:
        provider = OpenAIProvider(
            base_url=LLM_BASE_URL,
            api_key="unused",
        )
        return OpenAIChatModel(model_name=LLM_MODEL, provider=provider)
    return LLM_MODEL


def build_agent() -> tuple[Agent, MCPToolset | None]:
    """Build the pydantic-ai agent with optional MCP server connection."""
    system_prompt = _build_system_prompt(_get_ai_backends().assistant.system_message)
    ai_agent = Agent(model=_build_model(), system_prompt=system_prompt)
    return ai_agent, None


def build_mcp_server(
    headers: dict[str, str] | None = None,
) -> MCPToolset | None:
    """Build an MCP server connection with forwarded auth headers."""
    if not MCP_SERVER_URL:
        return None
    return MCPToolset(MCP_SERVER_URL, headers=headers or {})


def has_backends() -> bool:
    """Check if AI backends are configured."""
    return bool(PORTKEY_API_KEY or LLM_BASE_URL)


def _run_prompt(system_prompt: str, user_content: str) -> str:
    """Run a one-shot prompt through the LLM and return the text response."""
    agent = Agent(
        model=_build_model(),
        system_prompt=system_prompt,
    )

    async def _call():
        result = await agent.run(user_content)
        return result.output

    return asyncio.run(_call())


def summarized_al_submission(report, lang="english", with_trace=False):
    """Summarize an Assemblyline submission report (executive summary)."""
    params = _get_ai_backends().executive_summary
    system_prompt = _build_system_prompt(params.system_message, lang)
    content = f"{params.task}\n\n## Assemblyline Report\n\n```yaml\n{yaml.dump(report)}\n```"
    text = _run_prompt(system_prompt, content)
    if with_trace:
        return {
            "trace": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": content},
                {"role": "assistant", "content": text},
            ],
            "truncated": False,
        }
    return {"content": text, "truncated": False}


def detailed_al_submission(report, lang="english", with_trace=False):
    """Produce a detailed technical analysis of an Assemblyline submission report."""
    params = _get_ai_backends().detailed_report
    system_prompt = _build_system_prompt(params.system_message, lang)
    content = f"{params.task}\n\n## Assemblyline Report\n\n```yaml\n{yaml.dump(report)}\n```"
    text = _run_prompt(system_prompt, content)
    if with_trace:
        return {
            "trace": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": content},
                {"role": "assistant", "content": text},
            ],
            "truncated": False,
        }
    return {"content": text, "truncated": False}


def summarize_code_snippet(code, lang="english", with_trace=False):
    """Summarize a code snippet, identifying suspicious behaviors."""
    params = _get_ai_backends().code
    system_prompt = _build_system_prompt(params.system_message, lang)
    content = f"{params.task}\n\n## Code snippet\n\n```\n{code}\n```"
    text = _run_prompt(system_prompt, content)
    if with_trace:
        return {
            "trace": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": content},
                {"role": "assistant", "content": text},
            ],
            "truncated": False,
        }
    return {"content": text, "truncated": False}
