#!/bin/bash
set -e

echo "=== Starting test MCP server ==="
python3 /opt/test_mcp_server.py &
MCP_PID=$!

# Wait for MCP server to be ready
for i in $(seq 1 30); do
    if curl -sf -o /dev/null --max-time 2 http://localhost:8081/sse 2>/dev/null; then
        echo "MCP server is ready"
        break
    fi
    # Also try a simple TCP check
    if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('localhost',8081)); s.close()" 2>/dev/null; then
        echo "MCP server is ready (port open)"
        break
    fi
    echo "Waiting for MCP server... ($i/30)"
    sleep 1
done

echo ""
echo "=== Running MCP agent tests ==="
export MCP_SERVER_URL=http://localhost:8081/sse
python3 /opt/test_mcp_agent.py
TEST_EXIT=$?

# Cleanup
kill $MCP_PID 2>/dev/null || true
exit $TEST_EXIT
