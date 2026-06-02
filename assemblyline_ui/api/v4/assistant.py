from assemblyline.odm.models.user import ROLES
from flask import request

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import AI_AGENT, AUDIT_LOG
from assemblyline_ui.helper.ai.base import APIException, EmptyAIResponse

SUB_API = 'assistant'

assistant_api = make_subapi_blueprint(SUB_API, api_version=4)
assistant_api._doc = "Perform operations on archived submissions"


@assistant_api.route("/", methods=["POST"])
@api_login(require_role=[ROLES.assistant_use])
def assistant_conversation(**kwargs):
    """
    Send a message to the AI assistant and expect a response

    Variables:
    None

    Arguments:
    lang           => Which language do you want the AI to respond in?

    Data Block:
    [
      {
        "role": "system",
        "content": "You are and AI Assistant..."
      },
      {
        "role": "user",
        "content": "Hello!"
      }
    ]

    API call example:
    /api/v4/assistant/

    Result example:
    [
      {
        "role": "system",
        "content": "You are and AI Assistant..."
      },
      {
        "role": "user",
        "content": "Hello!"
      },
      {
        "role": "assistant",
        "content": "Hello! How can I assist you today?"
      }
    ]
    """
    user = kwargs['user']
    lang = request.args.get('lang', 'english')
    messages = request.json

    if not isinstance(messages, list):
        return make_api_response({}, "Input messages are not in the right format", 400)
    if not messages:
        return make_api_response({}, "No conversation messages provided", 400)

    # Ensure AI integration with Assemblyline is not abused by enforcing the presence of a system message
    first_message = messages[0]
    if first_message['role'] != 'system' or first_message['content'] != AI_AGENT.config.ui.ai_backends.function_params.assistant.system_message:
        # First message must be a system prompt to ensure proper context
        # Sanitize the rest of the conversation to ensure there isn't anything overriding the system prompt
        messages = [{
            'role': 'system',
            'content': AI_AGENT.config.ui.ai_backends.function_params.assistant.system_message,
        }] + [msg for msg in messages if msg['role'] != 'system']

    for message in messages:
        if 'role' not in message or 'content' not in message:
            return make_api_response({}, "Input messages are not in the right format", 400)

    # Special auditing task
    for message in messages[::-1]:
        if message['role'] == "user":
            AUDIT_LOG.info(
                f"{user['uname']} [{user['classification']}] :: assistant_conversation(content={message['content']})")
            break

    return make_api_response(AI_AGENT.continued_ai_conversation(messages, lang=lang))


@assistant_api.route("/agents/", methods=["GET"])
@api_login(require_role=[ROLES.assistant_use])
def list_agent_profiles(**kwargs):
    """
    List available AI agent profiles and their capabilities.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/assistant/agents/

    Result example:
    [
      {
        "name": "investigation",
        "description": "Investigate files and submissions using AL data"
      }
    ]
    """
    if not AI_AGENT.has_agent_profiles():
        return make_api_response([], "No agent profiles configured", 200)

    return make_api_response(AI_AGENT.get_agent_profile_list())


@assistant_api.route("/agents/<agent_name>/", methods=["POST"])
@api_login(require_role=[ROLES.assistant_use])
def agentic_conversation(agent_name, **kwargs):
    """
    Run an agentic conversation with tool calling using a named agent profile.

    The agent will iteratively call tools (search indices, inspect files, call
    external APIs) to answer the user's question. Tools and agent profiles are
    configured by the deployer via values.yaml.

    Variables:
    agent_name     => Name of the agent profile to use

    Arguments:
    lang           => Which language do you want the AI to respond in?

    Data Block:
    [
      {
        "role": "user",
        "content": "What processes were running in memory dump abc123...?"
      }
    ]

    API call example:
    /api/v4/assistant/agents/investigation/

    Result example:
    {
      "trace": [...],
      "truncated": false
    }
    """
    user = kwargs['user']
    lang = request.args.get('lang', 'english')
    messages = request.json

    if not isinstance(messages, list):
        return make_api_response({}, "Input messages are not in the right format", 400)
    if not messages:
        return make_api_response({}, "No conversation messages provided", 400)

    if not AI_AGENT.has_agent_profiles():
        return make_api_response({}, "No agent profiles configured on this system", 400)

    # Check if the agent profile exists
    profile = AI_AGENT.agent_profiles.get(agent_name)
    if not profile:
        return make_api_response({}, f"Unknown agent profile: {agent_name}", 404)

    # Check additional role requirement if configured
    if profile.require_role and profile.require_role not in user.get('roles', []):
        return make_api_response({}, f"Missing required role: {profile.require_role}", 403)

    # Validate message format — allow tool messages in agentic trace
    for message in messages:
        if 'role' not in message:
            return make_api_response({}, "Input messages are not in the right format", 400)
        if message['role'] not in ('user', 'assistant', 'system', 'tool'):
            return make_api_response({}, f"Invalid message role: {message['role']}", 400)

    # Audit the latest user message
    for message in messages[::-1]:
        if message['role'] == "user":
            AUDIT_LOG.info(
                f"{user['uname']} [{user['classification']}] :: "
                f"agentic_conversation(agent={agent_name}, content={message.get('content', '')})")
            break

    try:
        result = AI_AGENT.agentic_conversation(agent_name, messages, user=user, lang=lang)
        return make_api_response(result)
    except APIException as e:
        return make_api_response({}, str(e), 400)
    except EmptyAIResponse as e:
        return make_api_response({}, str(e), 404)
