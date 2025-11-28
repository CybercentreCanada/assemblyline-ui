from assemblyline.odm.models.user import ROLES
from flask import request

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import AI_AGENT, AUDIT_LOG

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
