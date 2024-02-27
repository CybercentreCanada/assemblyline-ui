from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.helper.ai import continued_ai_conversation
from flask import request

SUB_API = 'assistant'

assistant_api = make_subapi_blueprint(SUB_API, api_version=4)
assistant_api._doc = "Perform operations on archived submissions"


@assistant_api.route("/", methods=["POST"])
@api_login()  # require_role=[ROLES.assistant_use])   Add an Assistant use role
def conversation(**_):
    """
    Send a message to the AI assistant and expect a response

    Variables:
    None

    Arguments:
    None

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
    messages = request.json

    if not isinstance(messages, list):
        return make_api_response({}, "Input messages are not in the right format", 400)

    for message in messages:
        if 'role' not in message or 'content' not in message:
            return make_api_response({}, "Input messages are not in the right format", 400)

    return make_api_response(continued_ai_conversation(messages))
