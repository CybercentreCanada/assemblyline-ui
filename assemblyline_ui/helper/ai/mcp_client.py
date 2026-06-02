"""
MCP (Model Context Protocol) client for AI agentic workflows.

Connects to registered MCP servers, discovers their tools via the MCP protocol,
and executes tool calls. MCP servers self-describe their capabilities, so no
manual tool parameter configuration is needed — just register the server URL.

Uses the official `mcp` Python SDK for protocol handling.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from assemblyline.odm.models.config import MCPServerRegistration

logger = logging.getLogger('assemblyline.ui.ai.mcp')


class _MCPServerConnection:
    """Manages a single MCP server connection in a dedicated thread.

    The MCP SDK's sse_client uses anyio task groups that require the async
    context manager to stay open for the lifetime of the connection. We run
    each server in its own thread with its own event loop so the async with
    block stays intact.
    """

    def __init__(self, name: str, url: str, transport: str, headers: dict, verify: bool = True):
        self.name = name
        self.url = url
        self.transport = transport
        self.headers = headers
        self.verify = verify
        self.tools: Dict[str, dict] = {}
        self._session = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._error: Optional[str] = None

    def start(self, timeout: float = 30):
        """Start the connection in a background thread. Blocks until ready or timeout."""
        logger.info(f"MCP server '{self.name}': connecting to {self.url}")
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            logger.error(f"MCP server '{self.name}': connection timed out after {timeout}s")
            raise TimeoutError(f"MCP server '{self.name}' did not connect within {timeout}s")
        if self._error:
            logger.error(f"MCP server '{self.name}': connection failed: {self._error}")
            raise ConnectionError(self._error)

    def _run_loop(self):
        """Thread entry: create event loop and run the MCP connection."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect())
        except Exception as e:
            logger.error(f"MCP server '{self.name}': background thread error: {e}")
            self._error = str(e)
            self._ready.set()

    async def _connect(self):
        """Connect to the MCP server and keep the connection alive."""
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        # Build factory that respects the verify setting
        def httpx_factory(**kwargs):
            import httpx
            kwargs.setdefault('verify', self.verify)
            return httpx.AsyncClient(**kwargs)

        async with sse_client(url=self.url, headers=self.headers,
                              httpx_client_factory=httpx_factory) as streams:
            if len(streams) == 3:
                read_stream, write_stream, _ = streams
            else:
                read_stream, write_stream = streams

            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                self._session = session

                # Discover tools
                tools_response = await session.list_tools()
                for tool in tools_response.tools:
                    self.tools[f"{self.name}.{tool.name}"] = {
                        'server': self.name,
                        'mcp_tool_name': tool.name,
                        'description': tool.description or '',
                        'input_schema': tool.inputSchema if hasattr(tool, 'inputSchema') else {},
                    }

                logger.info(f"MCP server '{self.name}': discovered {len(tools_response.tools)} tools")
                self._ready.set()

                # Keep connection alive until the thread is stopped
                try:
                    while True:
                        await asyncio.sleep(1)
                except asyncio.CancelledError:
                    logger.debug(f"MCP server '{self.name}': connection thread cancelled")

    async def call_tool(self, tool_name: str, arguments: dict) -> Any:
        """Execute a tool call. Must be called from the server's own event loop."""
        if not self._session:
            raise RuntimeError(f"No session for MCP server '{self.name}'")
        return await self._session.call_tool(tool_name, arguments=arguments)

    def call_tool_sync(self, tool_name: str, arguments: dict, timeout: float = 120) -> Any:
        """Execute a tool call from any thread, dispatching to the server's event loop."""
        if not self._loop or not self._session:
            logger.error(f"MCP server '{self.name}': no active connection for tool call '{tool_name}'")
            raise RuntimeError(f"No active connection for MCP server '{self.name}'")
        future = asyncio.run_coroutine_threadsafe(
            self._session.call_tool(tool_name, arguments=arguments),
            self._loop
        )
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            logger.error(f"MCP server '{self.name}': tool call '{tool_name}' timed out after {timeout}s")
            raise

    def stop(self):
        """Stop the connection."""
        logger.info(f"MCP server '{self.name}': shutting down")
        if self._loop:
            for task in asyncio.all_tasks(self._loop):
                self._loop.call_soon_threadsafe(task.cancel)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)


class MCPToolRegistry:
    """Discovers and executes tools from registered MCP servers.

    Each MCP server runs in a dedicated background thread with its own event
    loop, keeping the SSE connection alive. Tool calls are dispatched to the
    correct server's event loop via thread-safe futures.
    """

    def __init__(self, mcp_servers: List['MCPServerRegistration']):
        self._servers: Dict[str, Any] = {}  # config objects
        self._connections: Dict[str, _MCPServerConnection] = {}
        self._tools: Dict[str, dict] = {}

        for server in mcp_servers:
            self._servers[server.name] = server

    def initialize(self):
        """Connect to all MCP servers and discover their tools. Synchronous."""
        logger.info(f"Initializing MCP connections for {len(self._servers)} server(s)")
        for name, server in self._servers.items():
            try:
                headers = dict(server.headers) if server.headers else {}

                # Inject FIC bearer token if configured
                if server.use_fic:
                    scope = server.fic_scope if hasattr(server, 'fic_scope') and server.fic_scope else 'https://cognitiveservices.azure.com/.default'
                    headers = self._inject_fic_token(name, headers, scope)

                verify = server.verify if hasattr(server, 'verify') else True
                conn = _MCPServerConnection(name, server.url, server.transport, headers, verify=verify)
                conn.start(timeout=server.timeout if hasattr(server, 'timeout') else 30)
                self._connections[name] = conn
                self._tools.update(conn.tools)
            except Exception as e:
                logger.error(f"Failed to connect to MCP server '{name}' at {server.url}: {e}")

    @staticmethod
    def _inject_fic_token(server_name: str, headers: dict, scope: str) -> dict:
        """Acquire a token via Federated Identity Credentials and inject into headers."""
        try:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()
            token = credential.get_token(scope).token
            headers['Authorization'] = f'Bearer {token}'
            logger.info(f"MCP server '{server_name}': acquired FIC token (scope={scope})")
        except ImportError:
            logger.warning(f"MCP server '{server_name}': azure-identity not installed, cannot use FIC")
        except Exception as e:
            logger.error(f"MCP server '{server_name}': FIC token acquisition failed: {e}")
        return headers

    def get_all_tool_names(self) -> List[str]:
        return list(self._tools.keys())

    def get_tools_for_servers(self, server_names: List[str]) -> List[str]:
        return [name for name, info in self._tools.items() if info['server'] in server_names]

    def filter_tools(self, server_names: List[str],
                     include: List[str] = None, exclude: List[str] = None) -> List[str]:
        available = self.get_tools_for_servers(server_names)
        if include:
            available = [t for t in available if t in include or t.split('.', 1)[-1] in include]
        if exclude:
            available = [t for t in available if t not in exclude and t.split('.', 1)[-1] not in exclude]
        return available

    def to_openai_tools(self, tool_names: List[str]) -> List[Dict]:
        openai_tools = []
        for name in tool_names:
            tool_info = self._tools.get(name)
            if not tool_info:
                continue
            schema = tool_info.get('input_schema', {})
            openai_tools.append({
                'type': 'function',
                'function': {
                    'name': name,
                    'description': tool_info['description'],
                    'parameters': schema if schema else {'type': 'object', 'properties': {}},
                }
            })
        return openai_tools

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Execute a tool call. Synchronous — dispatches to the server's event loop."""
        tool_info = self._tools.get(tool_name)
        if not tool_info:
            logger.warning(f"Tool call for unknown tool: {tool_name}")
            return json.dumps({'error': f'Unknown tool: {tool_name}'})

        server_name = tool_info['server']
        mcp_tool_name = tool_info['mcp_tool_name']

        conn = self._connections.get(server_name)
        if not conn:
            logger.error(f"No active connection for MCP server '{server_name}' (tool: {tool_name})")
            return json.dumps({'error': f'No active connection for MCP server: {server_name}'})

        try:
            result = conn.call_tool_sync(mcp_tool_name, arguments)

            texts = []
            for block in result.content:
                if hasattr(block, 'text'):
                    texts.append(block.text)
                elif hasattr(block, 'data'):
                    texts.append(f'[binary data: {len(block.data)} bytes]')

            output = '\n'.join(texts) if texts else json.dumps({'result': 'empty'})
            if len(output) > 64 * 1024:
                logger.warning(f"Tool '{tool_name}' response truncated from {len(output)} to 64KB")
                output = output[:64 * 1024] + '\n... [truncated]'
            return output

        except Exception as e:
            logger.exception(f"MCP tool execution failed: {tool_name}")
            return json.dumps({'error': f'Tool execution failed: {type(e).__name__}: {e}'})

    def close(self):
        """Close all MCP server connections."""
        logger.info(f"Closing {len(self._connections)} MCP connection(s)")
        for conn in self._connections.values():
            conn.stop()
        self._connections.clear()
