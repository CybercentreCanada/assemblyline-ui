"""AG-UI compatible SSE endpoint for TanStack AI useChat."""

import asyncio
import json
import queue
import threading
import uuid

from assemblyline.odm.models.user import ROLES
from flask import Response, request

from assemblyline_ui.api.base import api_login, make_subapi_blueprint
from assemblyline_ui.config import AI_AGENT, AUDIT_LOG
from assemblyline_ui.helper.ai import build_mcp_server

SUB_API = "assistant"

assistant_api = make_subapi_blueprint(SUB_API, api_version=4)
assistant_api._doc = "AI assistant chat endpoint using AG-UI protocol"

_SENTINEL = object()


def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _extract_user_message(messages: list) -> str:
    """Extract the last user message from AG-UI message format."""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            parts = msg.get("parts", [])
            for part in parts:
                if part.get("type") == "text":
                    content = part.get("content", "")
                    if content:
                        return content
            # Fallback to content field
            if msg.get("content"):
                return msg["content"]
    return "Hello"


def _build_message_history(messages: list):
    """Convert AG-UI message history (excluding the last message) to pydantic-ai ModelMessage format."""
    from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart

    def _text(msg: dict) -> str:
        for part in msg.get("parts", []):
            if part.get("type") == "text" and part.get("content"):
                return part["content"]
        return msg.get("content", "")

    history = []
    for msg in messages[:-1]:
        role = msg.get("role")
        text = _text(msg)
        if not text:
            continue
        if role == "user":
            history.append(ModelRequest(parts=[UserPromptPart(text)]))
        elif role == "assistant":
            history.append(ModelResponse(parts=[TextPart(content=text)]))
    return history


@assistant_api.route("/chat", methods=["POST"])
@api_login(require_role=[ROLES.assistant_use], check_xsrf_token=False)
def assistant_chat(**kwargs):
    """
    AG-UI compatible SSE streaming chat endpoint.

    Data Block:
    {
      "messages": [...],
      "runId": "optional-uuid"
    }

    Returns: SSE stream with AG-UI protocol events
    """
    user = kwargs["user"]
    body = request.json
    lang = request.args.get("lang", "english")

    messages = body.get("messages", [])
    run_id = body.get("runId", str(uuid.uuid4()))

    user_message = _extract_user_message(messages)
    prompt = (
        f"Please respond in {lang}.\n\n{user_message}"
        if lang.lower() != "english"
        else user_message
    )

    # Capture headers now while request context is active.
    # Extract XSRF token from the cookie (double-submit pattern) since
    # the frontend doesn't send the header on this endpoint (check_xsrf_token=False).
    xsrf_token = request.headers.get("X-XSRF-TOKEN", "") or request.cookies.get(
        "XSRF-TOKEN", ""
    )
    fwd_headers = {
        "Cookie": request.headers.get("Cookie", ""),
        "X-XSRF-TOKEN": xsrf_token,
        "X-Forwarded-For": request.headers.get(
            "X-Forwarded-For", request.remote_addr or ""
        ),
        "User-Agent": request.headers.get("User-Agent", ""),
    }

    # Audit
    AUDIT_LOG.info(
        f"{user['uname']} [{user['classification']}] :: assistant_chat(lang={lang}, content={user_message})"
    )

    def generate():
        message_id = str(uuid.uuid4())

        yield _sse_event({"type": "RUN_STARTED", "runId": run_id})
        yield _sse_event(
            {
                "type": "TEXT_MESSAGE_START",
                "messageId": message_id,
                "role": "assistant",
            }
        )

        # Use a thread + queue to bridge async streaming into the sync generator.
        # agent.run() with event_stream_handler runs the FULL agent loop (including
        # tool calls) while streaming text deltas in real-time.
        chunk_queue = queue.Queue()

        def _run_stream():
            # Persists across multiple _handle_events calls (one per model turn).
            emitted_any_text = [False]

            async def _handle_events(ctx, events):
                from pydantic_ai.messages import (
                    PartDeltaEvent,
                    PartStartEvent,
                    TextPart,
                    TextPartDelta,
                )

                text_part_count = 0
                seen_tool_call = False

                async for event in events:
                    if isinstance(event, PartStartEvent):
                        if isinstance(event.part, TextPart):
                            # Inject separator when transitioning from a tool call,
                            # either within this turn or from a previous model turn.
                            if (text_part_count > 0 and seen_tool_call) or (
                                text_part_count == 0 and emitted_any_text[0]
                            ):
                                chunk_queue.put("\n\n")
                                seen_tool_call = False
                            if event.part.content:
                                chunk_queue.put(event.part.content)
                                emitted_any_text[0] = True
                            text_part_count += 1
                        else:
                            seen_tool_call = True
                    elif isinstance(event, PartDeltaEvent) and isinstance(
                        event.delta, TextPartDelta
                    ):
                        if event.delta.content_delta:
                            chunk_queue.put(event.delta.content_delta)
                            emitted_any_text[0] = True

            async def _async_run():
                message_history = _build_message_history(messages)
                mcp = build_mcp_server(headers=fwd_headers)
                if mcp:
                    async with mcp:
                        await AI_AGENT.run(
                            prompt,
                            message_history=message_history,
                            toolsets=[mcp],
                            event_stream_handler=_handle_events,
                        )
                else:
                    await AI_AGENT.run(
                        prompt,
                        message_history=message_history,
                        event_stream_handler=_handle_events,
                    )

            try:
                asyncio.run(_async_run())
            except BaseException as e:
                # Extract real cause from TaskGroup/ExceptionGroup wrappers
                cause = e
                while hasattr(cause, "exceptions") and cause.exceptions:
                    cause = cause.exceptions[0]
                chunk_queue.put(f"Error: {type(cause).__name__}: {cause}")
            finally:
                chunk_queue.put(_SENTINEL)

        thread = threading.Thread(target=_run_stream, daemon=True)
        thread.start()

        # Drain the queue, yielding chunks as they arrive
        while True:
            try:
                item = chunk_queue.get(timeout=120)
            except queue.Empty:
                # Connection keepalive — send a comment to prevent timeout
                yield ": keepalive\n\n"
                continue
            if item is _SENTINEL:
                break
            yield _sse_event(
                {
                    "type": "TEXT_MESSAGE_CONTENT",
                    "messageId": message_id,
                    "content": item,
                }
            )

        yield _sse_event(
            {
                "type": "TEXT_MESSAGE_END",
                "messageId": message_id,
            }
        )
        yield _sse_event(
            {
                "type": "RUN_FINISHED",
                "runId": run_id,
                "finishReason": "stop",
            }
        )

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
