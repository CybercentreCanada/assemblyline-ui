from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.config import AIQueryParams
import requests
import yaml

from assemblyline_ui.config import config, LOGGER


class APIException(Exception):
    pass


class EmptyAIResponse(Exception):
    pass


def _call_ai_backend(data, params: AIQueryParams, action):
    # Build chat completions request
    data = {
        "max_tokens": params.max_tokens,
        "messages": [
            {"role": "system", "content": params.system_message},
            # TODO: we may have to do token detection and split the data in chunks...
            {"role": "user", "content": data},
        ],
        "model": config.ui.ai.model_name,
        "stream": False
    }
    data.update(params.options)

    try:
        # Call API
        resp = requests.post(config.ui.ai.chat_url, headers=config.ui.ai.headers, json=data)
    except Exception as e:
        message = f"An exception occured while trying to {action} with AI on server {config.ui.ai.chat_url}. [{e}]"
        LOGGER.warning(message)
        raise APIException(message)

    if not resp.ok:
        msg_data = resp.json()
        msg = msg_data.get('error', {}).get('message', None) or msg_data
        message = f"The AI API denied the request to {action} with the following message: {msg}"
        LOGGER.warning(message)
        raise APIException(message)

    # Get AI responses
    responses = resp.json()['choices']
    if responses:
        content = responses[0]['message']['content']
        reason = responses[0]['finish_reason']
        return {'content': content, 'truncated': reason == 'length'}

    raise EmptyAIResponse("There was no response returned by the AI")


def detailed_al_submission(report):
    return _call_ai_backend(yaml.dump(report),
                            config.ui.ai.detailed_report, "create detailed analysis of the AL report")


def summarized_al_submission(report):
    return _call_ai_backend(yaml.dump(report), config.ui.ai.executive_summary, "summarize the AL report")


def summarize_code_snippet(code):
    return _call_ai_backend(safe_str(code), config.ui.ai.code, "summarize code snippet")
