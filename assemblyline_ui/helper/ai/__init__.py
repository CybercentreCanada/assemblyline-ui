"""Pydantic AI agent for Assemblyline assistant."""

import asyncio
import os

import yaml
from openai import AsyncOpenAI
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider

# Environment-driven configuration
LLM_MODEL = os.environ.get("LLM_MODEL", None)
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", None)
PORTKEY_API_KEY = os.environ.get("PORTKEY_API_KEY", None)
PORTKEY_GATEWAY_URL = os.environ.get("PORTKEY_GATEWAY_URL", "")
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", None)

SYSTEM_PROMPT = (
    "You are a malware analyst assistant with access to an Assemblyline instance. "
    "Use the available tools to investigate files, alerts, and submissions. "
    "When analyzing results, focus on actionable findings: IOCs, detection rationale, "
    "and recommended next steps. Be concise but thorough."
)

SUMMARY_SYSTEM_PROMPT = (
    "You are an expert malware analyst. Your task is to summarize Assemblyline analysis results "
    "in clear, concise language suitable for an executive audience. Focus on the verdict, "
    "key indicators of compromise, and recommended actions."
)

DETAILED_SYSTEM_PROMPT = (
    "You are an expert malware analyst. Your task is to provide a detailed technical analysis "
    "of Assemblyline results. Include all relevant IOCs, behavioral indicators, MITRE ATT&CK mappings, "
    "and a thorough explanation of findings from each service."
)

CODE_SUMMARY_SYSTEM_PROMPT = (
    "You are a code analysis expert. Your task is to summarize what the given code snippet does, "
    "identify any potentially malicious behaviors, obfuscation techniques, or suspicious patterns."
)


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
        return OpenAIModel(model_name=LLM_MODEL, provider=provider)
    if LLM_BASE_URL:
        provider = OpenAIProvider(
            base_url=LLM_BASE_URL,
            api_key="unused",
        )
        return OpenAIModel(model_name=LLM_MODEL, provider=provider)
    return LLM_MODEL


def build_agent() -> tuple[Agent, MCPServerStreamableHTTP | None]:
    """Build the pydantic-ai agent with optional MCP server connection."""
    ai_agent = Agent(
        model=_build_model(),
        system_prompt=SYSTEM_PROMPT,
    )

    return ai_agent, None


def build_mcp_server(
    headers: dict[str, str] | None = None,
) -> MCPServerStreamableHTTP | None:
    """Build an MCP server connection with forwarded auth headers."""
    if not MCP_SERVER_URL:
        return None
    return MCPServerStreamableHTTP(url=MCP_SERVER_URL, headers=headers or {})


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
    content = (
        f"Summarize the following Assemblyline report in {lang}.\n\n"
        f"## Assemblyline Report\n\n```yaml\n{yaml.dump(report)}\n```"
    )
    text = _run_prompt(SUMMARY_SYSTEM_PROMPT, content)
    if with_trace:
        return {
            "trace": [
                {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
                {"role": "user", "content": content},
                {"role": "assistant", "content": text},
            ],
            "truncated": False,
        }
    return {"content": text, "truncated": False}


def detailed_al_submission(report, lang="english", with_trace=False):
    """Produce a detailed technical analysis of an Assemblyline submission report."""
    content = (
        f"Provide a detailed technical analysis of the following Assemblyline report in {lang}.\n\n"
        f"## Assemblyline Report\n\n```yaml\n{yaml.dump(report)}\n```"
    )
    text = _run_prompt(DETAILED_SYSTEM_PROMPT, content)
    if with_trace:
        return {
            "trace": [
                {"role": "system", "content": DETAILED_SYSTEM_PROMPT},
                {"role": "user", "content": content},
                {"role": "assistant", "content": text},
            ],
            "truncated": False,
        }
    return {"content": text, "truncated": False}


def summarize_code_snippet(code, lang="english", with_trace=False):
    """Summarize a code snippet, identifying suspicious behaviors."""
    content = (
        f"Summarize the following code snippet in {lang}.\n\n"
        f"## Code snippet\n\n```\n{code}\n```"
    )
    text = _run_prompt(CODE_SUMMARY_SYSTEM_PROMPT, content)
    if with_trace:
        return {
            "trace": [
                {"role": "system", "content": CODE_SUMMARY_SYSTEM_PROMPT},
                {"role": "user", "content": content},
                {"role": "assistant", "content": text},
            ],
            "truncated": False,
        }
    return {"content": text, "truncated": False}
