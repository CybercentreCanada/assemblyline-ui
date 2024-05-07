from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import AUDIT_LOG, AI_AGENT
from flask import request

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
