"""
Test MCP server for validating the AL agentic AI framework.

Run this, then point the AL config at it to test tool discovery and execution.

Usage:
    pip install mcp
    python test_mcp_server.py

The server exposes three dummy tools that simulate what a real AL MCP server would provide.
"""
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Mount, Route
import json
import uvicorn

app_server = Server("test-assemblyline-mcp")


@app_server.list_tools()
async def list_tools():
    return [
        Tool(
            name="search_index",
            description="Search an Assemblyline datastore index with a Lucene query",
            inputSchema={
                "type": "object",
                "properties": {
                    "index": {
                        "type": "string",
                        "description": "Which index to search",
                        "enum": ["alert", "file", "result", "signature", "submission"]
                    },
                    "query": {
                        "type": "string",
                        "description": "Lucene query string"
                    },
                    "rows": {
                        "type": "integer",
                        "description": "Max results (1-100)"
                    }
                },
                "required": ["index", "query"]
            }
        ),
        Tool(
            name="get_file_info",
            description="Get file metadata by SHA256",
            inputSchema={
                "type": "object",
                "properties": {
                    "sha256": {
                        "type": "string",
                        "description": "SHA256 hash of the file"
                    }
                },
                "required": ["sha256"]
            }
        ),
        Tool(
            name="submit_url",
            description="Submit a URL for analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to download and analyze"
                    }
                },
                "required": ["url"]
            }
        ),
    ]


@app_server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "search_index":
        # Return fake search results
        return [TextContent(
            type="text",
            text=json.dumps({
                "total": 2,
                "items": [
                    {
                        "sha256": "a" * 64,
                        "file_type": "executable/windows/pe64",
                        "size": 245760,
                        "max_score": 750
                    },
                    {
                        "sha256": "b" * 64,
                        "file_type": "document/office/word",
                        "size": 51200,
                        "max_score": 100
                    }
                ]
            }, indent=2)
        )]

    elif name == "get_file_info":
        sha256 = arguments.get("sha256", "unknown")
        return [TextContent(
            type="text",
            text=json.dumps({
                "sha256": sha256,
                "file_type": "executable/windows/pe64",
                "size": 245760,
                "magic": "PE32+ executable (GUI) x86-64, for MS Windows",
                "entropy": 6.8,
                "labels": ["malware", "trojan"],
                "seen": {"count": 3, "first": "2026-05-01", "last": "2026-06-01"}
            }, indent=2)
        )]

    elif name == "submit_url":
        url = arguments.get("url", "unknown")
        return [TextContent(
            type="text",
            text=json.dumps({
                "sid": "test-submission-id-12345",
                "sha256": "c" * 64,
                "status": "submitted",
                "message": f"URL '{url}' submitted for analysis"
            }, indent=2)
        )]

    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]


# Wire up SSE transport
sse = SseServerTransport("/messages/")

async def handle_sse(request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await app_server.run(streams[0], streams[1], app_server.create_initialization_options())

starlette_app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
    ]
)

if __name__ == "__main__":
    print("Starting test MCP server on http://localhost:8081")
    print("  SSE endpoint: http://localhost:8081/sse")
    print("  Tools: search_index, get_file_info, submit_url")
    print()
    uvicorn.run(starlette_app, host="0.0.0.0", port=8081)
