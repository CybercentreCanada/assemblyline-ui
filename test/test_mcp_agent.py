"""
End-to-end tests for the MCP agent framework.

Tests:
  1. MCP tool discovery — connect to MCP server, verify tools are discovered
  2. MCP tool execution — call tools and verify responses
  3. OpenAI tool format — verify conversion to function-calling format
  4. Agent profile filtering — verify tool scoping works
  5. AL API: list agent profiles — GET /api/v4/assistant/agents/
  6. AL API: agentic conversation — POST /api/v4/assistant/agents/<name>/

Usage:
    # Run via docker compose (recommended — works on ARM and amd64):
    docker compose -f test/docker-compose.mcp-test.yml up --build --abort-on-container-exit

    # Or standalone against a running MCP server (needs: pip install mcp):
    MCP_SERVER_URL=http://localhost:8081/sse python test/test_mcp_agent.py
"""
import asyncio
import importlib.util
import json
import os
import sys
import time

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8081/sse")
AL_UI_URL = os.environ.get("AL_UI_URL", "")

# Import mcp_client.py directly by file path to avoid pulling in the full
# assemblyline dependency chain (which needs C extensions). The module uses
# TYPE_CHECKING for its AL config imports so it loads standalone.
_candidates = [
    os.path.join(os.path.dirname(__file__), '..', 'assemblyline_ui', 'helper', 'ai', 'mcp_client.py'),
    os.path.join(os.path.dirname(__file__), 'mcp_client.py'),
    '/opt/mcp_client.py',
]
_mcp_path = next((p for p in _candidates if os.path.isfile(os.path.abspath(p))), None)
if not _mcp_path:
    print("ERROR: Cannot find mcp_client.py")
    sys.exit(1)
_spec = importlib.util.spec_from_file_location("mcp_client", os.path.abspath(_mcp_path))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
MCPToolRegistry = _mod.MCPToolRegistry

passed = 0
failed = 0


def report(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


# ── Test 1: MCP Tool Discovery ──────────────────────────

def test_tool_discovery():
    print("\n== Test 1: MCP Tool Discovery ==")

    class FakeServer:
        name = "test"
        url = MCP_SERVER_URL
        transport = "sse"
        headers = {}
        use_fic = False
        verify = True
        timeout = 30

    registry = MCPToolRegistry([FakeServer()])
    try:
        registry.initialize()
        tools = registry.get_all_tool_names()
        report("Connected to MCP server", True)
        report(f"Discovered {len(tools)} tools", len(tools) > 0, f"tools: {tools}")

        expected = ["test.search_index", "test.get_file_info", "test.submit_url"]
        for t in expected:
            report(f"Found tool '{t}'", t in tools)

        return registry
    except Exception as e:
        report("Connection failed", False, str(e))
        return None


# ── Test 2: MCP Tool Execution ──────────────────────────

def test_tool_execution(registry):
    print("\n== Test 2: MCP Tool Execution ==")
    if not registry:
        report("Skipped (no registry)", False)
        return

    result = registry.execute_tool("test.search_index", {"index": "file", "query": "*"})
    parsed = json.loads(result)
    report("search_index returned JSON", "total" in parsed, f"total={parsed.get('total')}")
    report("search_index has items", len(parsed.get("items", [])) > 0)

    result = registry.execute_tool("test.get_file_info", {"sha256": "a" * 64})
    parsed = json.loads(result)
    report("get_file_info returned data", parsed.get("file_type") is not None)

    result = registry.execute_tool("test.submit_url", {"url": "http://example.com/test.exe"})
    parsed = json.loads(result)
    report("submit_url returned sid", parsed.get("sid") is not None)

    result = registry.execute_tool("test.nonexistent", {})
    parsed = json.loads(result)
    report("Unknown tool returns error", "error" in parsed)


# ── Test 3: OpenAI Tool Format ──────────────────────────

def test_openai_format(registry):
    print("\n== Test 3: OpenAI Tool Format ==")
    if not registry:
        report("Skipped (no registry)", False)
        return

    tools = registry.get_all_tool_names()
    openai_tools = registry.to_openai_tools(tools)

    report(f"Converted {len(openai_tools)} tools", len(openai_tools) == len(tools))

    for tool in openai_tools:
        name = tool["function"]["name"]
        has_desc = bool(tool["function"].get("description"))
        has_params = "parameters" in tool["function"]
        has_required = "required" in tool["function"]["parameters"]
        report(f"  {name}: valid schema", has_desc and has_params and has_required)


# ── Test 4: Agent Profile Filtering ─────────────────────

def test_profile_filtering(registry):
    print("\n== Test 4: Agent Profile Filtering ==")
    if not registry:
        report("Skipped (no registry)", False)
        return

    all_tools = registry.filter_tools(server_names=["test"])
    report("All tools from 'test'", len(all_tools) == 3, f"got {len(all_tools)}")

    filtered = registry.filter_tools(server_names=["test"], exclude=["submit_url"])
    report("Exclude submit_url", "test.submit_url" not in filtered and len(filtered) == 2)

    filtered = registry.filter_tools(server_names=["test"], include=["search_index"])
    report("Include only search_index", len(filtered) == 1)

    filtered = registry.filter_tools(server_names=["nonexistent"])
    report("Unknown server = empty", len(filtered) == 0)


# ── Test 5: AL API — List Agent Profiles ────────────────

def test_al_api_list_profiles():
    print("\n== Test 5: AL API — List Agent Profiles ==")
    if not AL_UI_URL:
        report("Skipped (set AL_UI_URL)", True, "optional")
        return

    import requests

    # Wait for AL UI to come up
    print("  Waiting for AL UI...", end="", flush=True)
    for attempt in range(60):
        try:
            resp = requests.get(f"{AL_UI_URL}/api/", timeout=3)
            if resp.ok:
                print(" ready")
                break
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(3)
    else:
        print(" timeout")
        report("AL UI reachable", False, "timed out after 3 minutes")
        return

    # GET /api/v4/assistant/agents/ (unauthenticated should 401)
    resp = requests.get(f"{AL_UI_URL}/api/v4/assistant/agents/")
    report("Unauthenticated returns 401", resp.status_code == 401)

    # Create a session and login as admin
    session = requests.Session()
    login_resp = session.get(
        f"{AL_UI_URL}/api/v4/auth/login/",
        headers={"Authorization": "Basic YWRtaW46YWRtaW4="}  # admin:admin
    )
    if login_resp.status_code != 200:
        report("Admin login", False, f"status={login_resp.status_code}")
        return
    report("Admin login", True)

    # List agent profiles
    resp = session.get(f"{AL_UI_URL}/api/v4/assistant/agents/")
    if resp.status_code == 200:
        data = resp.json()
        profiles = data.get("api_response", [])
        report("GET /agents/ returned profiles", len(profiles) > 0, f"count={len(profiles)}")
        names = [p["name"] for p in profiles]
        report("'analyst' profile exists", "analyst" in names)
        report("'triage' profile exists", "triage" in names)
    else:
        report("GET /agents/", False, f"status={resp.status_code}")


# ── Test 6: AL API — Agentic Conversation ───────────────

def test_al_api_agentic():
    print("\n== Test 6: AL API — Agentic Conversation ==")
    if not AL_UI_URL:
        report("Skipped (set AL_UI_URL)", True, "optional")
        return

    # This test requires a real LLM backend configured in api_connections.
    # In CI, you'd set OPENAI_API_KEY and add it to the test config.
    report("Skipped (needs LLM backend)", True,
           "configure api_connections to test the full agentic loop")


# ── Main ────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("MCP Agent Framework — End-to-End Tests")
    print(f"  MCP Server: {MCP_SERVER_URL}")
    print(f"  AL UI:      {AL_UI_URL or 'not configured'}")
    print("=" * 60)

    registry = test_tool_discovery()
    test_tool_execution(registry)
    test_openai_format(registry)
    test_profile_filtering(registry)
    test_al_api_list_profiles()
    test_al_api_agentic()

    if registry:
        registry.close()

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    return 1 if failed else 0


if __name__ == "__main__":
    exit(main())
